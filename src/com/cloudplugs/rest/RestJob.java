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

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * @brief An instance of this class is an enqueued request execution obtained by {@link RestBaseManager#getJobOf(int)}.
 */
public class RestJob implements Future<Response>, Runnable
{
	protected RestJob(RestSpooler spooler, Request request, int timeout, RestCallback cb) {
		this.spooler = spooler;
		this.request = request;
		this.timeout = timeout;
		this.cb      = cb;
	}

	/**
	 * Runnable implementation executed in the spooler thread.
	 * Do not directly invoke this method.
	 */
	@Override
	public final void run() {
		response = RestSpooler.doRequest(request, timeout);
		if(cb != null) cb.on(request, response);
	}

	/**
	 * Attempts to cancel execution of this task.  This attempt will
	 * fail if the task has already completed, has already been cancelled,
	 * or could not be cancelled for some other reason. If successful,
	 * and this task has not started when <tt>cancel</tt> is called,
	 * this task should never run.  If the task has already started,
	 * then the <tt>mayInterruptIfRunning</tt> parameter determines
	 * whether the thread executing this task should be interrupted in
	 * an attempt to stop the task.
	 * <p></p>
	 * <p>After this method returns, subsequent calls to {@link #isDone} will
	 * always return <tt>true</tt>.  Subsequent calls to {@link #isCancelled}
	 * will always return <tt>true</tt> if this method returned <tt>true</tt>.
	 *
	 * @param mayInterruptIfRunning <tt>true</tt> if the thread executing this
	 *                              task should be interrupted; otherwise, in-progress tasks are allowed
	 *                              to complete
	 * @return <tt>false</tt> if the task could not be cancelled,
	 * typically because it has already completed normally;
	 * <tt>true</tt> otherwise
	 */
	@Override
	public boolean cancel(boolean mayInterruptIfRunning) {
		return cancel();
	}

	public boolean cancel() {
		if(response!=null || request.id==ID_NULL) return false;
		boolean res = spooler.cancel(request.id);
		if(res) request.id = ID_NULL;
		return res;
	}

	/**
	 * Returns <tt>true</tt> if this task was cancelled before it completed
	 * normally.
	 *
	 * @return <tt>true</tt> if this task was cancelled before it completed
	 */
	@Override
	public boolean isCancelled() {
		return response==null && request.id==ID_NULL;
	}

	/**
	 * Returns <tt>true</tt> if this task completed.
	 * <p></p>
	 * Completion may be due to normal termination, an exception, or
	 * cancellation -- in all of these cases, this method will return
	 * <tt>true</tt>.
	 *
	 * @return <tt>true</tt> if this task completed
	 */
	@Override
	public boolean isDone() {
		return response!=null || request.id==ID_NULL;
	}

	/**
	 * Waits if necessary for the computation to complete, and then
	 * retrieves its result.
	 *
	 * @return the computed result
	 * @throws java.util.concurrent.ExecutionException    if the computation threw an
	 *                               exception
	 * @throws InterruptedException  if the current thread was interrupted
	 *                               while waiting
	 */
	@Override
	public Response get() throws InterruptedException, ExecutionException {
		try {
			return get(0, null);
		} catch(Exception e) {
			return null;
		}
	}

	/**
	 * Waits if necessary for at most the given time for the computation
	 * to complete, and then retrieves its result, if available.
	 *
	 * @param timeout the maximum time to wait
	 * @param unit    the time unit of the timeout argument
	 * @return the computed result
	 * @throws java.util.concurrent.ExecutionException    if the computation threw an
	 *                               exception
	 * @throws InterruptedException  if the current thread was interrupted
	 *                               while waiting
	 * @throws java.util.concurrent.TimeoutException      if the wait timed out
	 */
	@Override
	public Response get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
		if(response == null) {
			int id = request.id;
			if(id != ID_NULL)
				spooler.waitFor(id, unit==null ? timeout : unit.toMillis(timeout));
		}
		return response;
	}

	/**
	 * Obtain the response of this job.
	 * @return the resulting HTTP response
	 */
	public Response getResponse() {
		try { return get(); }
		catch(Exception e) { return null; }
	}

	/**
	 * Retrieve the request of this job.
	 * @return the produced HTTP request of this job
	 */
	public Request getRequest() {
		return request;
	}

	/**
	 * Retrieve the connection timeout applied when sending the HTTP request of this job.
	 * @return the connection timeout in seconds
	 */
	public int getTimeout() {
		return timeout;
	}

	/**
	 * Retrieve the callback to invoke upon the competition of this job.
	 * @return the callback or null if there is no callback associated to this job
	 */
	public RestCallback getCallback() {
		return cb;
	}

	private RestSpooler  spooler;
	private Request      request;
	private Response     response;
	private RestCallback cb;
	private int          timeout;

	private static final int ID_NULL = RestSpooler.ID_NULL;
}

