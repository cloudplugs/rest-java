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

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.cloudplugs.rest.RestManager;

/**
 * @brief Tool class for validating parameters for making remote requests.
 * Every method throws an IllegalArgumentException if the given argument is not valid.
 * This class is for internal usage.
 */
public final class Validate
{
	public static final int MIN_PASS_LENGTH = 4;
	public static final int MIN_HWID_LENGTH = 1;

	public static void oid(String id) {
		if(!PlugId.isOid(id)) throw new IllegalArgumentException("null id");
	}

	public static void oids(String[] ids) {
		if(ids == null) throw new IllegalArgumentException("null id array");
		int n = ids.length;
		if(n == 0) throw new IllegalArgumentException("empty id array");
		while(--n >= 0)
			if(!PlugId.isOid(ids[n]))
				throw new IllegalArgumentException("invalid id at array index "+n);
	}

	public static void plugIds(String[] idPlugs) {
		if(idPlugs == null) throw new IllegalArgumentException("null device plug id array");
		int n = idPlugs.length;
		if(n == 0) throw new IllegalArgumentException("empty plug id array");
		while(--n >= 0)
			if(!PlugId.is(idPlugs[n]))
				throw new IllegalArgumentException("invalid plug id at array index "+n);
	}

	public static void devIds(String[] idPlugs) {
		if(idPlugs == null) throw new IllegalArgumentException("null device plug id array");
		int n = idPlugs.length;
		if(n == 0) throw new IllegalArgumentException("empty device plug id array");
		while(--n >= 0)
			if(!PlugId.isDev(idPlugs[n]))
				throw new IllegalArgumentException("invalid device plug id at array index "+n);
	}

	public static void devId(String idPlug) {
		if(!PlugId.isDev(idPlug)) throw new IllegalArgumentException("invalid device plug id");
	}

	public static void devIdCsv(String idPlugCsv) {
		if(!PlugId.isDevCsv(idPlugCsv)) throw new IllegalArgumentException("invalid device plug id");
	}

	public static void modelId(String idPlug) {
		if(!PlugId.isModel(idPlug)) throw new IllegalArgumentException("invalid model plug id");
	}

	public static void plugId(String idPlug) {
		if(!PlugId.is(idPlug)) throw new IllegalArgumentException("invalid plug id");
	}

	public static void plugIdCsv(String idPlugCsv) {
		if(!PlugId.isCsv(idPlugCsv)) throw new IllegalArgumentException("invalid plug id");
	}

	public static void channelMask(String channel) {
		if(!Channel.isMask(channel)) throw new IllegalArgumentException("invalid channel mask");
	}

	public static void channelName(String channel) {
		if(!Channel.isName(channel)) throw new IllegalArgumentException("invalid channel name");
	}

	public static void hwid(String hwid, String name) {
		str(hwid, MIN_HWID_LENGTH, name);
	}
	public static void hwid(String hwid) {
		hwid(hwid, "hwid");
	}

	public static void pass(String pass) {
		str(pass, MIN_PASS_LENGTH, "pass");
	}

	public static void body(String body) {
		json(body, "invalid body", false);
	}

	public static void json(String json, String msg, boolean allowNull) {
		if(json == null) {
			if(allowNull) return;
		} else if(Json.is(json)) {
			return;
		}
		throw new IllegalArgumentException(msg==null ? "invalid json" : msg);
	}

	public static void prop(String prop) {
		str(prop, 1, "prop");
	}

	public static void name(String name) {
		str(name, 1, "name");
	}

	public static void status(String status) {
		if(RestManager.STATUS_OK.equals(status) || RestManager.STATUS_DISABLED.equals(status) ||
			RestManager.STATUS_REACTIVATE.equals(status)) return;
		throw new IllegalArgumentException("invalid status");
	}

	public static void perm(JSONObject perm) {
		if(perm != null) {
			int e = 0;
			int n = perm.length();
			if(perm.has("of")) {
				try {
					subperm("of", perm.get("of"));
					e++;
				} catch(JSONException ex) {}
			}
			if(perm.has("ch")) {
				try {
					subperm("ch", perm.get("ch"));
					e++;
				} catch(JSONException ex) {}
			}
			if(perm.has("ctrl")) {
				try {
					Object ctrl = perm.get("ctrl");
					if(ctrl == null || "rw".equals(ctrl) || "r".equals(ctrl) || "".equals(ctrl)) e++;
					else throw new IllegalArgumentException("invalid perm.ctrl: it must be null, an empty string, \"rw\" or \"r\"");
				} catch(JSONException ex) {
					throw new IllegalArgumentException("invalid json: unable to read perm.ctrl");
				}
			}
			if(n == e) return;
		}
		throw new IllegalArgumentException("invalid perm: it must be null or a JSONObject containing only \"of\", \"ch\" and/or \"ctrl\" fields");
	}

	private static void subperm(String name, Object o) {
		if(o == null) return;
		if(o instanceof JSONObject) {
			JSONObject perm = (JSONObject)o;
			int e = 0;
			int n = perm.length();
			if(perm.has("r")) {
				try {
					Object r = perm.get("r");
					if(r == null || r instanceof JSONArray) e++;
					else throw new IllegalArgumentException("invalid perm." + name + "." + ".r: it must be null or JSONArray");
				} catch(JSONException ex) {
					throw new IllegalArgumentException("invalid json: unable to read perm." + name + 'r');
				}
			}
			if(perm.has("w")) {
				try {
					Object w = perm.get("w");
					if(w == null || w instanceof JSONArray) e++;
					else throw new IllegalArgumentException("invalid perm." + name + "." + ".w: it must be null or JSONArray");
				} catch(JSONException ex) {
					throw new IllegalArgumentException("invalid json: unable to read perm." + name + 'w');
				}
			}
			if(n == e) return;
		}
		throw new IllegalArgumentException("invalid perm field \""+name+"\": it must be null or a JSONObject containing only \"r\" and/or \"w\" fields (each one can be null or JSONArray)");
	}

	public static void str(String str, int minLength, String name) {
		if(str == null) throw new IllegalArgumentException("null "+name);
		if(str.length() < minLength) throw new IllegalArgumentException("empty "+name);
	}

	public static void pos(int num, String name) {
		if(num < 0) throw new IllegalArgumentException("negative "+name);
	}
}
