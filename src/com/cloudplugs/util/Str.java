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

import java.util.regex.Pattern;

/**
 * @brief Tool class to simplify some String operations.
 * This class is for internal usage.
 */
public final class Str
{
	public static String join(Object[] arr, String sep) {
		if(arr == null) return null;
		int n = arr.length;
		if(n <= 0) return null;
		StringBuilder sb = new StringBuilder(1024).append(arr[0]);
		for(int i=1; i<n; ++i)
			sb.append(sep).append(arr[i]);
		return sb.toString();
	}

	public static String csv(Object[] arr) {
		return join(arr, ",");
	}

	public static Pattern regexExact(String exp) {
		return Pattern.compile('^' + exp + '$');
	}

	public static Pattern regexCsv(String exp) {
		return Pattern.compile('^' + exp + "(?:," + exp + ")*$");
	}

	private Str() {}
}
