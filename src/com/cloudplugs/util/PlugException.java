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

import java.io.PrintWriter;
import java.io.StringWriter;


/**
 * @brief A generic exception of CloudPlugs library.
 */
public class PlugException extends RuntimeException
{
	private static final long serialVersionUID = 0xC704D00717L;

	public PlugException() {}

	public PlugException(String msg) {
		super(msg);
	}

	public PlugException(Throwable t) {
		super(t);
	}

	public PlugException(String msg, Throwable t) {
		super(msg, t);
	}

	/**
	 * @return the stack-track String of this exception
	 * @see #getStackTraceOf(Throwable)
	 */
	public String getStackTraceString() {
		return getStackTraceOf(this);
	}

	/**
	 * Convenient class method to obtain the stack-trace String of a Throwable
	 * @param t a Throwable to obtain the stack-track
	 * @return a printable stack-trace String rappresent the calling stack when the Throwable was been thrown
	 */
	public static String getStackTraceOf(Throwable t) {
		StringWriter sw = new StringWriter();
		t.printStackTrace(new PrintWriter(sw));
		return sw.toString();
	}
}
