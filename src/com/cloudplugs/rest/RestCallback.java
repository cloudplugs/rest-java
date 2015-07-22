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

/**
 * @brief An instance of this interface will asynchronously receive the results of a HTTP request execution
 * enqueued using one of the methods in {@link RestManager}.
 */
public interface RestCallback
{
	/**
	 * This method will be called after completing a request (enqueued by {@link RestManager}).
	 * This method is executed in the thread of the underlying spooler processes the enqueued requests.
	 * @param request the generated request
	 * @param response the received response from the server
	 */
	public void on(Request request, Response response);

	/**
	 * @brief Helper class to aggregate the execution of more {@link RestCallback}s into a single Object.
	 */
	public static class Join implements RestCallback
	{
		/**
		 * @param cbs the callbacks to aggregate
		 */
		public Join(RestCallback... cbs) {
			this.cbs = cbs;
		}

		/**
		 * @return the contained callbacks by this callbacks collector
		 */
		public RestCallback[] getCallbacks() {
			return cbs;
		}

		/**
		 * Implement this callback by invoking all {@link RestCallback#on} methods of the aggregated callbacks.
		 */
		@Override
		public void on(Request request, Response response) {
			for(RestCallback cb : cbs)
				if(cb != null)
					cb.on(request, response);
		}

		/** the aggregated callbacks */
		protected final RestCallback[] cbs;
	}

	/**
	 * @brief Helper class for easy dealing between threads when using {@link RestCallback}.
	 *
	 * This class implements {@link RestCallback} and encapsulates a given instance of {@link RestCallback}.
	 * Subclass must implement the abstract method {@link #enqueue(Runnable)} for enqueueing the execution of the callback
	 * in another thread, let's call it thread T (for instance the GUI thread), so that the encapsulated {@link RestCallback}
	 * will be executed in thread T instead of the underlying spooler thread of {@link RestManager}.
	 */
	public abstract class Meta implements RestCallback
	{
		/**
		 * @param cb the REST callback to encapsulated
		 */
		public Meta(RestCallback cb) {
			setCallback(cb);
		}

		/**
		 * @return the encapsulated REST callback by this instance
		 */
		public RestCallback getCallback() {
			return cb;
		}

		/**
		 * Set the encapsulated REST callback by this instance.
		 * @param cb the REST callback to encapsulated
		 */
		public void setCallback(RestCallback cb) {
			if(cb == null) throw new NullPointerException("null callback");
			this.cb = cb;
		}

		/**
		 * Enqueue an instance of {@link java.lang.Runnable} in another thread.
		 * @param runnable the runnable to execute
		 */
		public abstract void enqueue(Runnable runnable);

		/**
		 * {@link RestCallback} implementation.
		 */
		@Override
		public final void on(final Request request, final Response response) {
			enqueue(new Runnable() {
				@Override
				public void run() {
					cb.on(request, response);
				}
			});
		}

		private RestCallback cb;
	}
}
