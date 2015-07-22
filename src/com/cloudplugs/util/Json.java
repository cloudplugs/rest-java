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
import org.json.JSONTokener;

/**
 * @brief Tool class to simplify operations on JSON objects and strings.
 * This is for internal usage.
 */
public final class Json
{
	public static Object cast(String str) throws JSONException, NumberFormatException {
		if(str==null || str.length()==0) return null;
		switch(str.charAt(0)) {
			case '{':
			case '[':
			case '"':
				return new JSONTokener(str).nextValue();
			case 'n':
				if("null".equals(str)) return null;
				return str;
			case 't':
				if("true".equals(str)) return true;
				return str;
			case 'f':
				if("false".equals(str)) return false;
				return str;
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
			case '-':
				return Double.parseDouble(str);
			default:
				return str;
		}
	}

	public static String esc(String str) {
		for(int i=0; i<escLength; i+=2)
			str = str.replace(escArr[i], escArr[i+1]);
		return str;
	}

	public static JSONObject obj(Object... args) throws JSONException {
		JSONObject jso = new JSONObject();
		for(int i=1, n=args.length; i<n; i+=2) {
			Object val = args[i];
			if(val == null) continue;
			if(val instanceof Object[]) val = arr(val);
			jso.put((String)args[i-1], val);
		}
		return jso;
	}

	public static JSONArray arr(Object obj) throws JSONException {
		Object[] arr = (Object[])obj;
		JSONArray res = new JSONArray();
		for(int i=0, n=arr.length; i<n; ++i)
			res.put(i, arr[i]);
		return res;
	}

	public static boolean is(String json) {
		if(json == null) return true;
		int n = json.length();
		if(n <= 0) return false;
		char c = json.charAt(0);
		switch(c) {
			case '{': return n>1 && json.charAt(n-1)=='}';
			case '[': return n>1 && json.charAt(n-1)==']';
			case '"': return n>1 && json.charAt(n-1)==c;
			case 'n': return "null" .equals(json);
			case 't': return "true" .equals(json);
			case 'f': return "false".equals(json);
			default :
				try {
					Double.parseDouble(json);
					return true;
				} catch(Exception e) {
					return false;
				}
		}
	}

	private static final String[] escArr = new String[] {
		"\\", "\\\\", "\"", "\\\"", "\n", "\\n", "\r", "\\r", "\t", "\\t"
	};

	private static final int escLength = escArr.length;
}
