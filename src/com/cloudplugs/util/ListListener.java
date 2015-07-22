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

import java.util.LinkedList;

/**
 * @brief This class is a list of {@link Listener}s. It's a convenient way to handle more listeners using just one.
 */
public class ListListener extends LinkedList<Listener> implements Listener
{
	@Override
	public void onStart() {
		for(Listener l : this)
			l.onStart();
	}

	@Override
	public void onStop() {
		for(Listener l : this)
			l.onStop();
	}

	@Override
	public void onPause() {
		for(Listener l : this)
			l.onPause();
	}

	@Override
	public void onResume() {
		for(Listener l : this)
			l.onResume();
	}

	@Override
	public void onReady() {
		for(Listener l : this)
			l.onReady();
	}

	@Override
	public void onIdle() {
		for(Listener l : this)
			l.onIdle();
	}

	@Override
	public void onErr(Throwable t) {
		for(Listener l : this)
			l.onErr(t);
	}

	@Override
	public void onEvt(Object evt, Object value) {
		for(Listener l : this)
			l.onEvt(evt, value);
	}
}
