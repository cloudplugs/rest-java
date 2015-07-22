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

import org.json.JSONArray;
import org.json.JSONObject;

import com.cloudplugs.util.Json;

/**
 * @brief An instance of this class is a HTTP response received by the server or a generic error response.
 */
public class Response
{
	/** Successful HTTP status code for generic requests */
	public static final int STATUS_OK = 200;
	/** Successful HTTP status code for creation requests */
	public static final int STATUS_CREATED = 201;
	/** Partial successful HTTP status code */
	public static final int STATUS_PARTIAL = 206;
	/** Another partial successful HTTP status code */
	public static final int STATUS_MULTI = 207;

	public static final int ERR_BAD_REQUEST      = 400;
	public static final int ERR_UNAUTHORIZED     = 401;
	public static final int ERR_PAYMENT_REQUIRED = 402;
	public static final int ERR_FORBIDDEN        = 403;
	public static final int ERR_NOT_FOUND        = 404;
	public static final int ERR_NOT_ALLOWED      = 405;
	public static final int ERR_NOT_ACCEPTABLE   = 406;
	public static final int ERR_INTERNAL         = 500;
	public static final int ERR_NOT_IMPLEMENTED  = 501;
	public static final int ERR_BAD_GATEWAY      = 502;
	public static final int ERR_UNAVAILABLE      = 503;

	/**
	 * Create a new HTTP response.
	 * @param status the received HTTP status code or an integer less that zero for unknown response
	 * @param msg the message of the status code
	 * @param body the received body of this response
	 */
	public Response(int status, String msg, String body) {
		this.status = status;
		this.msg    = msg;
		this.body   = body==null ? null : body.trim();
	}

	/**
	 * @return true if the corresponding request was really sent to server
	 */
	public boolean isCompleted() {
		return status > 0;
	}

	/**
	 * @return true if the corresponding request was successful
	 */
	public boolean isSuccess() {
		return status==STATUS_OK || status==STATUS_CREATED;
	}

	/**
	 * @return true if the corresponding request has been partially successful and partially failed
	 */
	public boolean isPartial() {
		return status==STATUS_PARTIAL || status==STATUS_MULTI;
	}

	/**
	 * @return true if the corresponding request was not successful (in other words failed or partially failed)
	 */
	public boolean isFailed() {
		return !isSuccess() && !isPartial();
	}

	/**
	 * @return true if the body of this response contains multiple values (array of JSON)
	 */
	public boolean isMultiple() {
		return body!=null && body.length()>0 && body.charAt(0)=='[';
	}

	/**
	 * HTTP status code getter.
	 * @return the HTTP status code of this response
	 */
	public int getStatus() {
		return status;
	}

	/**
	 * HTTP status message getter.
	 * @return the HTTP status message of this response
	 */
	public String getMsg() {
		return msg;
	}

	/**
	 * HTTP body getter.
	 * @return the HTTP body of this response or null for empty body
	 */
	public String getBody() {
		return body;
	}

	/**
	 * HTTP body getter as JSON instance.
	 * @return the response body as a JSON instance, it can be an instance of {@link org.json.JSONObject},
	 *         {@link org.json.JSONArray}, java.lang.Number, java.lang.Boolean, java.lang.String
	 *         or null for empty body
	 */
	public Object getBodyAsJson() {
		if(bodyJson == null) {
			if(body==null || body.length()==0) return null;
			try {
				bodyJson = Json.cast(body);
			} catch(Exception e) {
				throw new RestException(e);
			}
		}
		return bodyJson;
	}

	/**
	 * HTTP body getter as a decoded JSON string value.
	 * @return the response body as a decoded JSON string value or null for empty body
	 * @throws RestException if the response body is not null and if it is a JSON string value
	 */
	public String getBodyAsString() {
		Object res = getBodyAsJson();
		if(res == null) return null;
		if(!(res instanceof String)) throw new RestException("response body is not a string");
		return (String)res;
	}

	/**
	 * Helper method to obtain an array of more responses.
	 * @return the multiple responses (or an array containing this response if it is not multiple)
	 * @throws RestException on error when decoding the JSON body of this response
	 */
	public Response[] getMultiple() {
		if(!isMultiple()) return new Response[]{ this };
		JSONArray arr = (JSONArray)getBodyAsJson();
		int n = arr.length();
		Response[] res = new Response[n];
		try {
			String body;
			for(int i=0; i<n; ++i) {
				Object el = arr.get(i);
				if(el == null)                    body = "null";
				else if(el instanceof JSONObject) body = ((JSONObject)el).toString(0);
				else if(el instanceof JSONArray ) body = ((JSONArray )el).toString(0);
				else if(el instanceof String    ) body = JSONObject.quote((String)el);
				else                              body = el.toString();
				res[i] = new Response(status, msg, body);
			}
		} catch(Exception e) {
			throw new RestException(e);
		}
		return res;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(1024);
		sb.append(status);
		if(msg !=null && msg .length()>0) sb.append(' ' ).append(msg );
		if(body!=null && body.length()>0) sb.append('\n').append(body);
		return sb.toString();
	}

	private final int status;
	private final String msg;
	private final String body;
	private Object bodyJson;
}
