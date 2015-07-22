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

/**
 * @brief Class for handling thrown exceptions during an asynchronous execution of this library.
 */
public class ErrHandler
{
	/**
	 * This method is called by an underlying thread of this library when unexpected exception is thrown.
	 * This default implementation prints the stack trace of the captured throwable.
	 * @param err the thrown exception to handle
	 */
	public void handleErr(Throwable err) {
		if(err != null)
			err.printStackTrace();
	}

	/**
	 * This is the default implementation of {@link ErrHandler}.
	 */
	public static final ErrHandler DEFAULT = new ErrHandler();

	/**
	 * This is the active implementation of {@link ErrHandler}.
	 * It is initialized as {@link #DEFAULT}.
	 * If null, any thrown exceptions from an asynchronous execution will be ignored.
	 */
	public static ErrHandler active = DEFAULT;
}
