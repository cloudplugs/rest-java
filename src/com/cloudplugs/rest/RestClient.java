package com.cloudplugs.rest;

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

import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;

import com.cloudplugs.util.Listener;
import com.cloudplugs.util.MultiListener;
import com.cloudplugs.util.Spooler;

/**
 * @brief This is the main class for handling the connection to the CloudPlugs server on the Java platform.
 * <br/><br/>
 * An instance of RestClient manages the HTTP requests flow by creating a thread spooler for each
 * server to connect. Such spooler will send enqueued HTTP requests one by one following the FIFO order.
 * An instance of this class will also emit events about the internal spooler behavior, so that any attached
 * {@link com.cloudplugs.util.Listener} to a RestClient will be notified about what's happening in the execution flow.
 * <br/><br/>
 * The primary usage of this class is to invoke the method {@link #getManager(Opts)} for obtaining an instance of
 * {@link RestManager} able to enqueue asynchronous HTTP requests (executed in an underlying thread spooler) using
 * the preferred options {@link Opts}.
 * <br/><br/>
 * Android developers should avoid a direct use of this class, they should use
 * {@link com.cloudplugs.rest.android.RestClient} (unavailable on Java platform), because it supports reliable
 * background execution of HTTP requests through a dedicated Android service and CPU wake locks.
 * By using a direct instance of this class, an Android app could lose the ability to send HTTP requests and to
 * receive the responses when the app is not in foreground.
 */
public class RestClient extends MultiListener
{
	/** Event String emitted each time a new underlying spooler is started from the first time. */
	public static final String EVT_START  = "start";
	/** Event String emitted each time an underlying spooler is stopped. */
	public static final String EVT_STOP   = "stop";
	/** Event String emitted each time an underlying spooler is paused. */
	public static final String EVT_PAUSE  = "pause";
	/** Event String emitted each time an underlying spooler is resumed. */
	public static final String EVT_RESUME = "resume";
	/** Event String emitted each time an underlying spooler become idle (the internal HTTP request queue becomes empty). */
	public static final String EVT_IDLE   = "idle";

	/**
	 * Create a new instance of this class.
	 */
	public RestClient() {
		this(RestSpooler.class);
	}

	protected RestClient(Class<? extends RestSpooler> cls) {
		if(cls == null) throw new NullPointerException("null spooler class");
		try {
			spoolerConstr = cls.getConstructor();
		} catch(Exception e) {
			throw new RestException(e);
		}
	}

	/**
	 * Create a new instance of {@link RestManager} able to make HTTP requests using the specified options in <tt>opts</tt>.
	 *
	 * @param opts the options used by the new {@link RestManager}
	 * @return a new {@link RestManager}
	 */
	public RestManager getManager(Opts opts) {
		RestSpooler spooler;
		String url = opts.getUrl();
		synchronized(spoolers) {
			spooler = spoolers.get(url);
			if(spooler == null)
				spoolers.put(url, spooler = newSpooler(url));
		}
		return new RestManager(spooler, opts);
	}

	/**
	 * @return true if at least one of the underlying thread spoolers has been started
	 */
	public boolean isStarted() {
		return started;
	}

	private RestSpooler newSpooler(String url) {
		try {
			RestSpooler spooler = spoolerConstr.newInstance();
			setSpoolerListener(spooler, url);
			spooler.start();
			return spooler;
		} catch(Exception e) {
			throw new RestException(e);
		}
	}

	/**
	 * Pause the execution of all threads of the underlying spoolers, if any is running.
	 * All already and future enqueued HTTP requests won't be sent over the network until this REST client will be resumed
	 * by calling {@link #resume()}.
	 * @return true if at least one spooler thread was been paused, false if no spooler thread was running
	 */
	public boolean pause() {
		boolean paused = false;
		synchronized(spoolers) {
			for(RestSpooler spooler : spoolers.values())
				paused |= spooler.pause();
		}
		if(paused) onPause();
		return paused;
	}

	/**
	 * Resume the execution of all threads of the underlying spoolers, if any has been paused.
	 * @return true if at least one spooler thread was been resumed, false if no spooler thread was paused
	 */
	public boolean resume() {
		boolean resumed = false;
		synchronized(spoolers) {
			for(RestSpooler spooler : spoolers.values())
				resumed |= spooler.resume();
		}
		if(resumed) onResume();
		return resumed;
	}

	/**
	 * Stop the execution of all threads of the underlying spoolers (if any) and clear all enqueued HTTP requests to send.
	 * This operation cannot be undone.
	 * @return true if at least one thread spooler has been stopped, false otherwise
	 */
	public boolean stop() {
		boolean stopped = false;
		synchronized(spoolers) {
			for(RestSpooler spooler : spoolers.values())
				stopped |= spooler.stop();
		}
		return stopped;
	}

	/**
	 * Stop this client (see {@link #stop()} for more details) and remove all {@link com.cloudplugs.util.Listener}s
	 * attached to this instance, if any.
	 */
	public void destroy() {
		stop();
		clearListeners();
	}

	/**
	 * Wait for the end of execution of all spoolers.
	 * The current thread will be suspended until all spoolers are stopped, but not more than <tt>timeout</tt> milliseconds.
	 * If this client has no spoolers, this method will return immediately.
	 * @param timeout expiration timeout: maximum milliseconds to wait or 0 to have no expiration
	 * @return true if all spoolers have beeen stopped, false if the <tt>timeout</tt> is expired
	 */
	public boolean waitForStop(long timeout) {
		synchronized(spoolers) {
			while(started) {
				try { spoolers.wait(timeout); }
				catch(InterruptedException e) { return false; }
			}
		}
		return true;
	}

	/**
	 * Like {@link #waitForStop(long)}, but without any timeout expiration.
	 */
	public void waitForStop() {
		waitForStop(0);
	}

	/**
	 * Override base class implementation.
	 * Do not call this method.
	 */
	@Override
	public void onStop() {
		super.onStop();
		synchronized(spoolers) {
			spoolers.notifyAll();
		}
	}

	private void setSpoolerListener(final Spooler spooler, final String url) {
		spooler.setListener(new Listener.Stub() {
			@Override
			public void onStart() {
				boolean first;
				synchronized(spoolers) {
					first = !started;
					started = true;
					spoolers.notifyAll();
				}
				RestClient.this.onEvt(EVT_START, spooler);
				if(first) RestClient.this.onStart();
			}
			@Override
			public void onStop() {
				synchronized(spoolers) {
					if(spoolers.remove(url) == null) return;
					boolean empty = spoolers.isEmpty();
					RestClient.this.onEvt(EVT_STOP, spooler);
					if(!empty) return;
					started = false;
					RestClient.this.onStop();
				}
			}
			@Override
			public void onPause() {
				RestClient.this.onEvt(EVT_PAUSE, spooler);
				if(hasOneSpooler()) RestClient.this.onPause();
			}
			@Override
			public void onResume() {
				RestClient.this.onEvt(EVT_RESUME, spooler);
				if(hasOneSpooler()) RestClient.this.onResume();
			}
			@Override
			public void onIdle() {
				RestClient.this.onEvt(EVT_IDLE, spooler);
				if(hasOneSpooler()) RestClient.this.onIdle();
			}
			@Override
			public void onErr(Throwable t) {
				RestClient.this.onErr(t);
			}
		});
	}

	private boolean hasOneSpooler() {
		synchronized(spoolers) {
			return spoolers.size() == 1;
		}
	}

	private volatile boolean started = false;
	private final Constructor<? extends RestSpooler> spoolerConstr;
	protected final Map<String,RestSpooler> spoolers = new HashMap<String,RestSpooler>();
}
