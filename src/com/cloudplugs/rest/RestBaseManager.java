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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Date;

import com.cloudplugs.util.Json;
import com.cloudplugs.util.MultiListener;
import com.cloudplugs.util.PlugId;
import com.cloudplugs.util.Timestamp;

/**
 * @brief Base class for handling HTTP requests.
 * This class is not intended for direct usage, the developer should use a subclass of this one.
 * <br/><br/>
 * An instance of this class will also emit events about the internal spooler behavoir, so that any attached
 * {@link com.cloudplugs.util.Listener} to a RestBaseManager will be notified about what's happening in the execution flow.
 * <br/><br/>
 * See also {@link RestManager}.
 */
public abstract class RestBaseManager extends MultiListener
{
	/**
	 * Constant to indicate an invalid asynchronous execution identifier.
	 */
	public static final int ID_NULL = RestSpooler.ID_NULL;

	protected RestBaseManager(RestSpooler spooler, Opts opts) {
		this.opts    = opts    == null ? new Opts()        : opts;
		this.spooler = spooler == null ? new RestSpooler() : spooler;
		this.spooler.ref();
	}

	/**
	 * @return options associated to this manager
	 */
	public Opts getOpts() {
		return opts;
	}

	/**
	 * Shortcut for getting the authentication identifier (PlugID or email) associated in the {@link Opts} of this manager.
	 * It's just like calling this.getOpts().getAuthId().
	 * @return authentication identifier or null if there is no authentication associated to this manager
	 */
	public String getAuthId() {
		return opts.getAuthId();
	}

	/**
	 * @return false if there is at least one pending request to execute, otherwise true
	 */
	public boolean isEmpty() {
		return spooler.isEmpty();
	}

	/**
	 * Retrieve an enqueued and pending asynchronous request as an instance of {@link RestJob}.
	 * @param id the identifier of the asynchronous execution to obtain
	 * @return the pending exection or null if not found (for unknown <tt>id</tt> or already executed requests)
	 */
	public RestJob getJobOf(int id) {
		return spooler.getJobOf(id);
	}

	/**
	 * Wait for the end of execution of the specified asynchronous pending request and return its {@link Response}.
	 * The current thread will be suspended until the request is completed or canceled, but not more than <tt>timeout</tt> milliseconds.
	 * If the specified pending request identifier is not valid, this method will return immediately.
	 * This method is like {@link #waitFor(int, long)} but it returns the obtained response.
	 * @param id the identifier asynchronous request to synchronize
	 * @param timeout expiration timeout: maximum milliseconds to wait or 0 to have no expiration
	 * @return the obtained response or null if the asyncronous execution <tt>id</tt> is unknown or if <tt>timeout</tt> is expired
	 */
	public Response sync(int id, long timeout) {
		try { return spooler.getJobOf(id).get(timeout, null); }
		catch(Exception e) { return null; }
	}

	/**
	 * Like {@link #sync(int, long)}, but without any timeout expiration.
	 * @param id the identifier asynchronous request to synchronize
	 * @return the obtained response or null if the asyncronous execution <tt>id</tt> is unknown
	 */
	public Response sync(int id) {
		return sync(id, 0);
	}

	/**
	 * Cancel the execution of a previously enqueued request.
	 * If successfull, all information about the enqueued request will be lost.
	 * @param id the identifier asynchronous request to cancel
	 * @return true if the specified request has been canceled, false if that request is unknown or already executed
	 */
	public boolean cancel(int id) {
		return spooler.cancel(id);
	}

	/**
	 * Cancel the execution of a previously enqueued request.
	 * If successful, all information about the enqueued request will be lost.
	 * @param request the request to cancel
	 * @return true if the specified request has been canceled, false if that request is unknown or already executed
	 */
	public boolean cancel(Request request) {
		return spooler.cancel(request.id);
	}

	/**
	 * Wait for the end of execution of the specified asynchronous pending request.
	 * The current thread will be suspended until the request is completed or canceled, but not more than <tt>timeout</tt> milliseconds.
	 * If the specified pending request identifier is not valid, this method will return immediately.
	 * @param id the identifier asynchronous request to synchronize
	 * @param timeout expiration timeout: maximum milliseconds to wait or 0 to have no expiration
	 * @return true if the asynchronous request has been completed or canceled, false if unknown
	 */
	public boolean waitFor(int id, long timeout) {
		return spooler.waitFor(id, timeout);
	}

	/**
	 * Like {@link #waitFor(int, long)}, but without any timeout expiration.
	 * @param id the identifier asynchronous request to synchronize
	 * @return true if the asynchronous request has been completed or canceled, false if unknown
	 */
	public boolean waitFor(int id) {
		return spooler.waitFor(id);
	}

	/**
	 * Wait for the end of execution of all asynchronous enqueued pending requests.
	 * The current thread will be suspended until all requests are completed, but not more than <tt>timeout</tt> milliseconds.
	 * @param timeout expiration timeout: maximum milliseconds to wait or 0 to have no expiration
	 * @return true if all asynchronous requests have been completed or canceled, false if the spooler thread is not running
	 *         (for example for empty queue) or if the <tt>timeout</tt> is expired
	 */
	public boolean waitForIdle(long timeout) {
		return spooler.waitForIdle(timeout);
	}

	/**
	 * Like {@link #waitForIdle(long)} but without expiration.
	 * @return true if all asynchronous requests have been completed or canceled, false if the spooler thread is not running
	 *         (for example for empty queue)
	 */
	public boolean waitForIdle() {
		return spooler.waitForIdle();
	}

	/**
	 * Wait for the end of execution of the underlying spooler thread of asynchronous requests.
	 * The current thread will be suspended until the underlying spooler will be stopped, but not more than <tt>timeout</tt> milliseconds.
	 * @param timeout expiration timeout: maximum milliseconds to wait or 0 to have no expiration
	 * @return false if the underlying spooler was already stopped
	 */
	public boolean waitForStop(long timeout) {
		return spooler.waitForStop(timeout);
	}

	/**
	 * Like {@link #waitForStop(long)} but without expiration.
	 * @return false if the underlying spooler was already stopped
	 */
	public boolean waitForStop() {
		return spooler.waitForStop();
	}

	protected RestSpooler getSpooler() {
		return spooler;
	}

	protected int execRequest(Request request, RestCallback cb) {
		return spooler.request(request, opts.getTimeout(), cb);
	}

	protected int execGet(String action, String path, RestCallback cb) {
		return execRequest(Request.GET, action, path, null, cb);
	}

	protected int execPut(String action, String path, String body, RestCallback cb) {
		return execRequest(Request.PUT, action, path, body, cb);
	}

	protected int execPost(String action, String path, String body, RestCallback cb) {
		return execRequest(Request.POST, action, path, body, cb);
	}

	protected int execPatch(String action, String path, String body, RestCallback cb) {
		return execRequest(Request.PATCH, action, path, body, cb);
	}

	protected int execDelete(String action, String path, String body, RestCallback cb) {
		return execRequest(Request.DELETE, action, path, body, cb);
	}

	protected int execRequest(String method, String action, String path, String body, RestCallback cb) {
		return spooler.request(opts, method, action, path, body, cb);
	}

	protected int execRequest(String method, String action, String path, RestCallback cb, Object... body) {
		return execRequest(method, action, path, bodyGen(body), cb);
	}

	@Override
	protected void finalize() throws Throwable {
		super.finalize();
		spooler.unref();
	}

	protected void wantAuth() {
		if(!opts.hasAuth()) throw new RestException("missing auth");
	}
	protected void wantBasicAuth() {
		if(opts.isAuthMaster()) throw new RestException("cannot be master auth");
		wantAuth();
	}
	protected void wantEmailAuth() {
		if(!opts.hasAuthEmail()) throw new RestException("missing email auth");
		wantAuth();
	}
	protected void wantMasterAuth() {
		if(!opts.isAuthMaster()) throw new RestException("missing master auth");
		wantAuth();
	}
	protected void wantDeviceAuth() {
		if(!PlugId.isDev(opts.getAuthId())) throw new RestException("missing device plug id in auth");
	}
	protected void wantNoEmailAuth() {
		if(opts.hasAuthEmail()) throw new RestException("cannot have auth");
		wantAuth();
	}
	protected void wantNoAuth() {
		if(opts.hasAuth()) throw new RestException("cannot have auth");
	}
	protected void wantNoDeviceAuth() {
		if(opts.hasAuthDevice()) throw new RestException("cannot have device auth");
	}

	protected static String bodyGen(Object... args) {
		try {
			int n = args.length;
			switch(n) {
				case 0:
					return null;
				case 1:
					Object val = args[0];
					if(val == null) return null;
					return (val instanceof Object[] ? Json.arr(val) : val).toString();
				default:
					if((n & 1) == 1) throw new IllegalArgumentException("wrong number of arguments: cannot be odd");
					return Json.obj(args).toString();
			}
		} catch(Exception e) {
			throw new IllegalArgumentException(e);
		}
	}

	protected static String queryGen(Object... args) {
		int n = args.length;
		if(n <= 0) return null;
		try {
			StringBuilder sb = new StringBuilder(1024);
			sb.append('?');
			Object val = queryCast(args[1]);
			if(val != null) sb.append(esc(args[0])).append('=').append(val);
			for(int i=2; i<n; i+=2) {
				val = queryCast(args[i + 1]);
				if(val != null) sb.append('&').append(esc(args[i])).append('=').append(val);
			}
			return sb.toString();
		} catch(Exception e) {
			throw new IllegalArgumentException(e);
		}
	}

	protected static String pathQuery(String path, String query) {
		if(query == null) return path;
		if(path  == null) return query.startsWith("?") ? query : '?'+query;
		return query.startsWith("?") ? path+query : path+'?'+query;
	}

	protected static String esc(Object s) throws UnsupportedEncodingException {
		return s==null ? null : URLEncoder.encode(s.toString(), "UTF-8");
	}

	protected static Object queryCast(Object o) throws UnsupportedEncodingException {
		if(o instanceof Number) {
			if(o instanceof Integer) {
				int i = ((Number)o).intValue();
				return i>0 ? o : null;
			}
			return o;
		}
		if(o instanceof Date) return ((Date)o).getTime();
		if(o instanceof Object[]) {
			Object[] arr = (Object[])o;
			int n = arr.length;
			if(n == 0) return null;
			StringBuilder sb = new StringBuilder();
			int i = -1;
			while(++i < n) {
				Object val = queryCast(arr[i]);
				if(val != null) {
					sb.append(val);
					break;
				}
			}
			if(i >= n) return null;
			while(++i < n)
				sb.append(',').append(queryCast(arr[i]));
			return sb.toString();
		}
		return esc(o);
	}

	protected static Object ts(Object val, String err) {
		return Timestamp.from(val, err);
	}

	protected static Object tso(Object val, String err) {
		return val instanceof String && PlugId.isOid((String)val) ? val : Timestamp.from(val, err);
	}

	protected static Object tsp(Object val, String err) {
		return val instanceof String && PlugId.is((String)val) ? val : Timestamp.from(val, err);
	}

	protected static void runOnCb(RestCallback cb, Runnable runnable) {
		if(cb!=null && cb instanceof RestCallback.Meta) {
			((RestCallback.Meta)cb).enqueue(runnable);
		} else {
			runnable.run();
		}
	}

	protected final Opts        opts;
	protected final RestSpooler spooler;
}
