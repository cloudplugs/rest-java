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

import java.net.MalformedURLException;
import java.net.URL;

import org.json.JSONObject;

import com.cloudplugs.util.PlugId;
import com.cloudplugs.util.Validate;


/**
 * @brief An instance of this class contains all the options for connecting and making requests to the server,
 * including the authentication credentials required for most HTTP requests.
 * This class mainly offers getter and setter methods to manage all the options.
 */
public final class Opts
{
	/** Key name of authentication identifier when importing or exporting options to JSON. */
	public static final String K_AUTHID = "authId";
	/** Key name of authentication password when importing or exporting options to JSON. */
	public static final String K_AUTHPASS = "authPass";
	/** Key name of master authentication when importing or exporting options to JSON. */
	public static final String K_AUTHMASTER = "authMaster";
	/** Key name of connection url when importing or exporting options to JSON. */
	public static final String K_URL = "url";
	/** Key name of connection timeout when importing or exporting options to JSON. */
	public static final String K_TIMEOUT = "timeout";

	/** The default SSL state: true if enabled, otherwise disabled. */
	public static final boolean DEF_SSL = Const.DEFAULT_URL.startsWith("https");
	/** The default connection url, it is the official CloudPlugs server. */
	public static final String DEF_URL = makeUrl(Const.DEFAULT_URL, DEF_SSL);
	/** The default connection timeout. */
	public static final int DEF_TIMEOUT  = Const.DEFAULT_TIMEOUT;
	/** The default authentication identifier. */
	public static final String DEF_AUTHID = Const.DEFAULT_AUTHID;
	/** The default authentication password. */
	public static final String DEF_AUTHPASS = Const.DEFAULT_AUTHPASS;
	/** The default master authentication. */
	public static final boolean DEF_AUTHMASTER = Const.DEFAULT_MASTER;

	/**
	 * Create a new instance using all the default values.
	 */
	public Opts() {}

	/**
	 * Create a new instance using the options in the specified instance of {@link org.json.JSONObject}.
	 * @param jso the JSON object to import
	 * @throws RestException for invalid argument
	 */
	public Opts(JSONObject jso) {
		fromJSON(jso);
	}

	/**
	 * Create a new instance using the options in the specified JSON string.
	 * @param json the JSON string to import
	 * @throws RestException for invalid argument
	 */
	public Opts(String json) {
		fromString(json);
	}

	/**
	 * Create a new instance by cloning the specified options
	 * @param opts the options to clone
	 * @throws java.lang.NullPointerException for null argument
	 */
	public Opts(Opts opts) {
		fromOpts(opts);
	}

	/**
	 * Connection URL option getter.
	 * @return the current connection URL string
	 */
	public String getUrl() {
		return url;
	}

	/**
	 * Connection URL option setter.
	 * @param url the new connection URL to use
	 * @return this instance
	 * @throws RestException for invalid url
	 */
	public Opts setUrl(String url) {
		this.url = makeUrl(url, ssl);
		this.ssl = this.url.charAt(4) == 's';
		return this;
	}

	/**
	 * @return true if the currenct connection URL is using HTTPS, false if using plain HTTP
	 */
	public boolean hasSSL() {
		return ssl;
	}

	/**
	 * Enable or disable SSL connection by changing the connection URL.
	 * @param enable true to enable SSL, false to disable it
	 * @return this instance
	 */
	public Opts enableSSL(boolean enable) {
		if(enable == ssl) return this;
		if(url == null) ssl = enable;
		else setUrl(url.substring(0,5)+(enable? "s"+url.substring(5) : url.substring(4)));
		return this;
	}

	/**
	 * @return true if this instance contains authentication id and password
	 */
	public boolean hasAuth() {
		return authId!=null && authPass!=null;
	}

	/**
	 * Authentication identifier getter.
	 * @return the current authentication identifier
	 */
	public String getAuthId() {
		return authId;
	}

	/**
	 * Authentication password getter.
	 * @return the current authentication password
	 */
	public String getAuthPass() {
		return authPass;
	}

	/**
	 * @return true if using master authentication
	 */
	public boolean isAuthMaster() {
		return authMaster;
	}

	/**
	 * @return true if using a PlugID as authentication identifier
	 */
	public boolean hasAuthDevice() {
		return PlugId.isDev(authId);
	}

	/**
	 * @return true if using an email as authentication identifier
	 */
	public boolean hasAuthEmail() {
		return authId!=null && authId.indexOf('@')>0;
	}

	/**
	 * Authentication setter.
	 * @param id the authentication identifier to set
	 * @param pass the authentication password to set
	 * @param master true if the given <tt>pass</tt> is a master password
	 * @return this instance
	 */
	public Opts setAuth(String id, String pass, boolean master) {
		if(id==null || (id.indexOf('@')<=0 && !PlugId.isDev(id))) throw new IllegalArgumentException("invalid id");
		Validate.pass(pass);
		authId     = id;
		authPass   = pass;
		authMaster = master;
		return this;
	}

	/**
	 * Authentication setter using the default master setting.
	 * @param id the authentication identifier to set
	 * @param pass the authentication password to set
	 * @return this instance
	 */
	public Opts setAuth(String id, String pass) {
		return setAuth(id, pass, DEF_AUTHMASTER);
	}

	/**
	 * Connection timeout getter.
	 * @return the current connection timeout in seconds
	 */
	public int getTimeout() {
		return timeout;
	}

	/**
	 * Connection timeout setter.
	 * @param timeout the connection timeout (in seconds) to set
	 * @return this instance
	 */
	public Opts setTimeout(int timeout) {
		this.timeout = timeout<=0 ? DEF_TIMEOUT : timeout;
		return this;
	}

	/**
	 * Import options from another <tt>Opts</tt> instance.
	 * @param opts the options to import
	 * @return this instance
	 * @throws NullPointerException if the argument is null
	 */
	public Opts fromOpts(Opts opts) {
		if(opts == null) throw new NullPointerException("null opts");
		url        = opts.url;
		ssl        = opts.ssl;
		authId     = opts.authId;
		authPass   = opts.authPass;
		authMaster = opts.authMaster;
		timeout    = opts.timeout;
		return this;
	}

	/**
	 * Alias of {@link #fromJSON(String)}.
	 * @param json the JSON string to import
	 * @return this instance
	 * @throws IllegalArgumentException for invalid JSON
	 */
	public Opts fromString(String json) {
		return fromJSON(json);
	}

	/**
	 * Import options from a JSON string.
	 * @param json the JSON string to import
	 * @return this instance
	 * @throws IllegalArgumentException for invalid JSON
	 */
	public Opts fromJSON(String json) {
		try {
			return fromJSON(new JSONObject(json));
		} catch(Exception e) {
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * Import options from a JSON object.
	 * @param jso the {@link org.json.JSONObject} to import
	 * @return this instance
	 * @throws IllegalArgumentException if fails
	 */
	public Opts fromJSON(JSONObject jso) {
		try {
			setUrl(jso.getString(K_URL));
			setAuth(jso.getString(K_AUTHID), jso.getString(K_AUTHPASS), jso.getBoolean(K_AUTHMASTER));
			setTimeout(jso.getInt(K_TIMEOUT));
			return this;
		} catch(Exception e) {
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * Export this instance as a JSON object.
	 * @return a new instance of {@link org.json.JSONObject} equivalent to this instance
	 * @throws RestException if fails
	 */
	public JSONObject toJSON() {
		try {
			JSONObject jso = new JSONObject();
			jso.put(K_AUTHID    , authId);
			jso.put(K_AUTHPASS  , authPass);
			jso.put(K_AUTHMASTER, authMaster);
			jso.put(K_URL       , url);
			jso.put(K_TIMEOUT   , timeout);
			return jso;
		} catch(Exception e) {
			throw new RestException(e);
		}
	}

	/**
	 * Export this instance as a JSON string.
	 * @return the JSON string equivalent to this instance
	 * @throws RestException if fails
	 */
	@Override
	public String toString() {
		return toJSON().toString();
	}

	private static String makeUrl(String url, Boolean ssl) {
		if(url == null) throw new NullPointerException("null url");
		if(url.length() < 8) throw new IllegalArgumentException("url too short");
		int p = url.indexOf("://");
		if(p==-1 || p>5) {
			if(ssl == null) ssl = DEF_SSL;
			url = (ssl ? "https://" : "http://") + url;
		} else {
			String proto = url.substring(0,p);
			if(!"http".equals(proto) && !"https".equals(proto))
				throw new IllegalArgumentException("unsupported url protocol: "+proto);
		}
		try {
			new URL(url);
		} catch(MalformedURLException e) {
			throw new IllegalArgumentException("malformed url");
		}
		if(url.charAt(url.length()-1) != '/') url += '/';
		return url;
	}

	private String  url        = DEF_URL;
	private String  authId     = DEF_AUTHID;
	private String  authPass   = DEF_AUTHPASS;
	private boolean authMaster = DEF_AUTHMASTER;
	private boolean ssl        = DEF_SSL;
	private int     timeout    = DEF_TIMEOUT;
}
