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
 * @brief Tool class containing internal default values and options.
 * This class is for internal usage.
 */
public class Const
{
	public static final String  DEFAULT_URL = "https://api.cloudplugs.com/iot/";

	public static final String  DEFAULT_AUTHID   = null;
	public static final String  DEFAULT_AUTHPASS = null;
	public static final boolean DEFAULT_MASTER   = false;
	public static final int     DEFAULT_TIMEOUT  = 60;

	public static final int ERR_CONN = -1;

	public static final String HEADER_PLUGID = "X-Plug-Id";
	public static final String HEADER_EMAIL  = "X-Plug-Email";
	public static final String HEADER_AUTH   = "X-Plug-Auth";
	public static final String HEADER_MASTER = "X-Plug-Master";

	public static final String USER_AGENT = "jCP";
}
