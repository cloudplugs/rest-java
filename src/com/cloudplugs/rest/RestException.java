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

import com.cloudplugs.util.PlugException;


/**
 * @brief An exception thrown by REST CloudPlugs API.
 */
public class RestException extends PlugException
{
	private static final long serialVersionUID = 0xC704D974653C3L;

	public RestException() {}

	public RestException(String msg) {
		super(msg);
	}

	public RestException(Throwable t) {
		super(t);
	}

	public RestException(String msg, Throwable t) {
		super(msg, t);
	}
}
