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
 * @brief Basic interface for receiving generic asyncronous CloudPlugs notifications and events.
 */
public interface Listener
{
	/** Invoked when a mechanism is started. */
	public void onStart();
	/** Invoked when a mechanism is stopped. */
	public void onStop();
	/** Invoked when a mechanism is paused. */
	public void onPause();
	/** Invoked when a mechanism is resumed. */
	public void onResume();
	/** Invoked when a mechanism is ready to be used. */
	public void onReady();
	/** Invoked when a mechanism become idle (usually a spooler). */
	public void onIdle();
	/** Invoked on generic events. */
	public void onEvt(Object evt, Object value);
	/** Invoked when an error occurs or when a callback throws an exception. */
	public void onErr(Throwable t);

	/**
	 * @brief Convenient stub class for fast {@link Listener} implementations.
	 * The implemented methods of this class just do nothing.
	 */
	public static class Stub implements Listener {
		public void onStart() {}
		public void onStop() {}
		public void onPause() {}
		public void onResume() {}
		public void onReady() {}
		public void onIdle() {}
		public void onEvt(Object evt, Object value) {}
		/** This default implementation passes the error to {@link com.cloudplugs.util.ErrHandler#active}. */
		public void onErr(Throwable t) {
			ErrHandler handler = ErrHandler.active;
			if(handler != null) handler.handleErr(t);
		}
	}
}
