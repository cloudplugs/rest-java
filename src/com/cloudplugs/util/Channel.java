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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.regex.Pattern;

/**
 * @brief Tool class for easy channel manipulation.
 * This class is for internal usage.
 */
public final class Channel
{
	/**
	 * @param channel the string to test
	 * @return true if the given argument is a valid channel mask
	 */
	public static boolean isMask(String channel) {
		return channel!=null && rexMask.matcher(channel).find();
	}

	/**
	 * @param channel the string to test
	 * @return true if the given argument is a valid channel name
	 */
	public static boolean isName(String channel) {
		return channel!=null && rexName.matcher(channel).find();
	}

	/**
	 * Escape the given channel to be used in the URL path
	 * @param channel the string to escape
	 * @return the escaped channel
	 */
	public static String toUrl(String channel) {
		try {
			return URLEncoder.encode(channel, "UTF-8");
		} catch(UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}

	private Channel() {}

	private static final Pattern rexName = Pattern.compile("^(([^/+#]+)/)*[^/+#]+$");
	private static final Pattern rexMask = Pattern.compile("^(([^/+#]+|\\+)/)*([^/+#]+|\\+|#)$");
}
