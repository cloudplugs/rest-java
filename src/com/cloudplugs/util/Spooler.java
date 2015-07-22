package com.cloudplugs.util;

/*<license>
Copyright 2014 CloudPlugs Inc.

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
</license>*/

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * @brief Generic job spooler implementation in a dedicated thread.
 * This class is for internal usage.
 */
public class Spooler extends MetaListener implements Runnable
{
	public  static final long THREAD_NULL = 0;
	public  static final int      ID_NULL = 0;
	private static final String ERR_THREAD_CALL = "forbidden call (wrong thread)";

	public Spooler() {}

	public Spooler(Listener l) {
		super(l);
	}

	public boolean isStarted() {
		return started;
	}

	public boolean isStopped() {
		return !started;
	}

	public boolean isQuitting() {
		return started && !running;
	}

	public synchronized boolean isAlive() {
		return thread!=null && thread.isAlive();
	}

	public boolean isPaused() {
		return paused;
	}

	public boolean isEmpty() {
		synchronized(jobs) {
			return jobs.isEmpty();
		}
	}

	public int size() {
		synchronized(jobs) {
			return jobs.size();
		}
	}

	public boolean getClearOnStop() {
		return clearOnStop;
	}

	public void setClearOnStop(boolean clearOnStop) {
		this.clearOnStop = clearOnStop;
	}

	public long idThread() {
		return thread==null ? THREAD_NULL : thread.getId();
	}

	public boolean isThisThread() {
		return thread!=null && thread.getId()==Thread.currentThread().getId();
	}

	public synchronized boolean start() {
		if(started) return false;
		started = true;
		running = true;
		thread  = new Thread(this);
		thread.start();
		return true;
	}

	public synchronized boolean stop() {
		if(!started || !running) return false;
		running = false;
		if(clearOnStop) clear();
		thread.interrupt();
		return true;
	}

	public boolean pause() {
		synchronized(lockPause) {
			if(paused) return false;
			paused = true;
		}
		return true;
	}

	public boolean resume() {
		synchronized(lockPause) {
			if(!paused) return false;
			paused = false;
			lockPause.notify();
		}
		return true;
	}

	public void clear() {
		synchronized(jobs) {
			Collection<Runnable> values = jobs.values();
			jobs.clear();
			for(Runnable job : values) {
				synchronized(job) {
					job.notifyAll();
				}
			}
		}
	}

	public int exec(Runnable job) {
		if(job == null) throw new NullPointerException("null job");
		int id;
		synchronized(jobs) {
			id = ++idLast;
			jobs.put(id, job);
			jobs.notify();
		}
		return id;
	}

	public boolean cancel(int id) {
		if(id <= ID_NULL) return false;
		synchronized(jobs) {
			Runnable job = jobs.remove(id);
			if(job == null) return false;
			if(id == idFirst+1) ++idFirst;
			synchronized(job) {
				job.notifyAll();
			}
		}
		return true;
	}

	public Runnable getJobOf(int id) {
		if(id <= ID_NULL) return null;
		synchronized(jobs) {
			return jobs.get(id);
		}
	}

	public boolean waitFor(int id) {
		return waitFor(id, 0);
	}

	public boolean waitFor(int id, long timeout) {
		if(isThisThread()) throw new RuntimeException(ERR_THREAD_CALL);
		Runnable job;
		synchronized(jobs) {
			if(id <= ID_NULL) id = idLast;
			else if(id < idLast) return true;
			job = jobs.get(id);
		}
		if(job == null) return false;
		synchronized(job) {
			synchronized(jobs) {
				if(id < idLast) return true;
				if(job != jobs.get(id)) return false;
			}
			try {
				job.wait(timeout);
			} catch(InterruptedException e) {
				return false;
			}
		}
		return true;
	}

	public boolean waitForIdle() {
		return waitForIdle(0);
	}

	public boolean waitForIdle(long timeout) {
		if(isThisThread()) throw new RuntimeException(ERR_THREAD_CALL);
		if(!started) return false;
		synchronized(lockIdle) {
			try {
				lockIdle.wait(timeout);
			} catch(InterruptedException e) {
				return false;
			}
		}
		return true;
	}

	public boolean waitForStop() {
		return waitForStop(0);
	}

	public boolean waitForStop(long timeout) {
		if(isThisThread()) throw new RuntimeException(ERR_THREAD_CALL);
		synchronized(lockStop) {
			while(started) {
				try { lockStop.wait(timeout); }
				catch(InterruptedException e) { return false; }
			}
		}
		return true;
	}

	@Override
	public void onIdle() {
		super.onIdle();
		synchronized(lockIdle) {
			lockIdle.notifyAll();
		}
	}

	@Override
	public void run() {
		if(!isThisThread()) throw new RuntimeException(ERR_THREAD_CALL);
		onStart();
		while(running && shouldSpool()) {
			Runnable job = null;
			synchronized(jobs) {
				while(job == null) {
					if(jobs.isEmpty()) {
						idFirst = idLast;
						onIdle();
						if(jobs.isEmpty()) {
							try {
								jobs.wait();
								if(!running) break;
								onReady();
							} catch(InterruptedException e) {
								break;
							}
						}
					} else {
						jobs.remove(idFirst);
					}
					job = jobs.get(++idFirst);
				}
			}
			if(job != null) {
				try { job.run(); }
				catch(Throwable t) { onErr(t); }
				synchronized(job) {
					synchronized(jobs) {
						jobs.remove(idFirst);
					}
					job.notifyAll();
				}
				Thread.yield();
			}
		}
		synchronized(this) {
			thread  = null;
			started = false;
			onStop();
			synchronized(lockIdle) {
				lockIdle.notifyAll();
			}
			synchronized(lockStop) {
				lockStop.notifyAll();
			}
		}
	}

	private boolean shouldSpool() {
		synchronized(lockPause) {
			if(paused) {
				try {
					onPause();
					while(paused)
						lockPause.wait();
					onResume();
				} catch(InterruptedException e) {
					return false;
				}
			}
		}
		return true;
	}

	private volatile boolean started     = false;
	private volatile boolean running     = false;
	private volatile boolean paused      = false;
	private volatile boolean clearOnStop = true;
	private          Thread  thread      = null;
	private volatile int     idFirst     = 0;
	private volatile int     idLast      = 0;
	private final    Object  lockIdle    = new Object();
	private final    Object  lockPause   = new Object();
	private final    Object  lockStop    = new Object();
	private final Map<Integer,Runnable> jobs = new HashMap<Integer,Runnable>();
}
