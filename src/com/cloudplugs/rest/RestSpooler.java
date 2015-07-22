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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import com.cloudplugs.util.Listener;
import com.cloudplugs.util.PlugException;
import com.cloudplugs.util.RefSpooler;
import com.cloudplugs.util.SSL;

/**
 * @brief A thread spooler for asynchronous sending of HTTP requests.
 * This class is for internal usage.
 */
public class RestSpooler extends RefSpooler
{
	public RestSpooler() {}

	public RestSpooler(Listener listener) {
		super(listener);
	}

	public int request(Opts opts, String method, String action, String path, String body, RestCallback cb) {
		if(path==null || path.length()==0) {
			path = action;
		} else if(action!=null && action.length()>0) {
			char c = path.charAt(0);
			if(c!='?' && c!='/') action += '/';
			path = action + path;
		}
		return request(opts, method, path, body, cb);
	}

	public int request(Opts opts, String method, String path, String body, RestCallback cb) {
		if(opts == null) throw new NullPointerException("null opts");
		if(method == null) throw new NullPointerException("null method");
		if(method.length() == 0) throw new IllegalArgumentException("empty method");
		Request request = new Request(method, opts.getUrl(), path==null ? "" : path, getHeaders(opts), body);
		return request(request, opts.getTimeout(), cb);
	}

	public int request(final Request request, final int timeout, final RestCallback cb) {
		return request.id = exec(new RestJob(this, request, timeout, cb));
	}

	@Override
	public RestJob getJobOf(int id) {
		return (RestJob)super.getJobOf(id);
	}

	protected static Response doRequest(Request request, int timeout) {
		Response response = null;
		InputStream    in = null;
		OutputStream  out = null;

		try {
			HttpURLConnection conn = (HttpURLConnection)new URL(request.getUrl()).openConnection();
			conn.setInstanceFollowRedirects(true);
			conn.setDoInput(true);

			if(timeout > 0) conn.setConnectTimeout(timeout * 1000);
			String  method  = request.getMethod();
			String  body    = request.getBody();
			boolean hasBody = body!=null && body.length()>0;

			if((hasBody && Request.DELETE.equals(method)) || Request.PATCH.equals(method)) {
				// NOTE: HttpURLConnection does not support PATCH nor DELETE with body
				conn.setRequestProperty("X-HTTP-Method-Override", method);
				method = Request.POST;
			}
			conn.setRequestMethod(method);

			String[] headers = request.getHeaders();
			if(headers != null)
				for(int i=1, n=headers.length; i<n; i+=2)
					conn.setRequestProperty(headers[i-1], headers[i]);
			conn.setRequestProperty("Accept", "application/json");
			conn.setRequestProperty("User-Agent", Const.USER_AGENT);

			if(hasBody) {
				byte[] bodyBytes = body.getBytes();
				conn.setRequestProperty("Content-Type", "application/json");
				conn.setDoOutput(true);
				conn.setFixedLengthStreamingMode(bodyBytes.length);
				out = new BufferedOutputStream(conn.getOutputStream());
				out.write(bodyBytes);
				out.flush();
			}

			try {
				in = new BufferedInputStream(conn.getInputStream());
			} catch(IOException e) {
				in = new BufferedInputStream(conn.getErrorStream());
			}
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			byte[] buf = new byte[BUF_LENGTH];
			try {
				for(int n; (n = in.read(buf, 0, BUF_LENGTH)) != -1;)
					baos.write(buf, 0, n);
			} catch(IOException e) {}
			baos.flush();
			body = new String(baos.toByteArray());

			response = new Response(conn.getResponseCode(), conn.getResponseMessage(), body);

		} catch(Exception e) {
			response = new Response(Const.ERR_CONN, e.getMessage(), PlugException.getStackTraceOf(e));

		} finally {
			if(in  != null) { try { in .close(); } catch(Exception e) {} }
			if(out != null) { try { out.close(); } catch(Exception e) {} }
		}

		return response;
	}

	private static String[] getHeaders(Opts opts) {
		String authId = opts.getAuthId();
		return authId == null ? null : new String[] {
			authId.indexOf('@')>0 ? Const.HEADER_EMAIL : Const.HEADER_PLUGID,
			authId,
			opts.isAuthMaster() ? Const.HEADER_MASTER : Const.HEADER_AUTH,
			opts.getAuthPass()==null ? "" : opts.getAuthPass(),
		};
	}

	static {
		try {
			SSL.trustCloudPlugs();
		} catch(Exception e) {
			e.printStackTrace();
		}
	}

	private static final int BUF_LENGTH = 8*1024;
}
