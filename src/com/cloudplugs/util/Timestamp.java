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

import java.util.Date;

/**
 * @brief Tool class for easy Timestamp validation and handling.
 * This class is for internal usage.
 */
public final class Timestamp
{
	public static Object from(Object val, String name) {
		if(val == null) return null;
		if(val instanceof Number) {
			long l = ((Number)val).longValue();
			return l<=0 ? null : val;
		}
		if(val instanceof Date)
			return ((Date)val).getTime();
		if(val instanceof String) {
			String str = (String)val;
			if(str.length() <= 0) return null;
			try {
				return Long.parseLong(str);
			} catch(NumberFormatException e) {
				return str;
			}
		}
		throw new IllegalArgumentException("invalid "+(name==null ? "argument" : name));
	}

	public static Object from(Object val) {
		return from(val, null);
	}

	public static Object[] toKeyValue(String kNum, String kDate, Object val) {
		if(val == null)
			return NULL_EXP;
		if(val instanceof Number) {
			long l = ((Number)val).longValue();
			if(l <= 0) return NULL_EXP;
			return new Object[]{ kNum , val };
		}
		if(val instanceof Date)
			return new Object[]{ kDate, ((Date)val).getTime() };
		String key;
		if(val instanceof String) {
			String str = (String)val;
			if(str.length() <= 0) return NULL_EXP;
			try {
				val = Long.parseLong(str);
				key = kNum;
			} catch(NumberFormatException e) {
				key = kDate;
			}
			return new Object[]{ key, val };
		}
		if(     kNum  == null     ) key = kDate;
		else if(kDate == null     ) key = kNum;
		else if(kNum.equals(kDate)) key = kNum;
		else                        key = kNum + '/' + kDate;
		throw new IllegalArgumentException("invalid "+key+" value: "+val);
	}

	private static final Object[] NULL_EXP = new Object[]{ null, null };

	private Timestamp() {}
}
