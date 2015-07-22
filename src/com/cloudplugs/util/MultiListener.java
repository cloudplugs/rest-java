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
 * @brief Convenient class combines the behaviors and the advantages of {@link ListListener} and {@link MetaListener}:
 * this is an instance of {@link MetaListener} encapsulates a {@link ListListener}.
 */
public class MultiListener extends MetaListener
{
	public MultiListener() {
		super(new Coll());
	}

	public boolean hasListener(Listener l) {
		if(l == null) return false;
		synchronized(listener) {
			return ((Coll)listener).contains(l);
		}
	}

	public Listener getListener(int location) {
		synchronized(listener) {
			return ((Coll)listener).get(location);
		}
	}

	public void addListener(Listener l) {
		if(l == null) throw new NullPointerException("null listener");
		synchronized(listener) {
			((Coll)listener).add(l);
		}
	}

	public boolean removeListener(Listener l) {
		if(l == null) return false;
		synchronized(listener) {
			return ((Coll)listener).remove(l);
		}
	}

	public Listener removeListener(int location) {
		synchronized(listener) {
			return ((Coll)listener).remove(location);
		}
	}

	public void clearListeners() {
		synchronized(listener) {
			((Coll)listener).clear();
		}
	}

	@Override
	public Listener getListener() {
		return this;
	}

	@Override
	public final void setListener(Listener l) {
		throw new RuntimeException("forbidden");
	}

	@Override
	public void onStart() {
		synchronized(listener) {
			super.onStart();
		}
	}

	@Override
	public void onStop() {
		synchronized(listener) {
			super.onStop();
		}
	}

	@Override
	public void onPause() {
		synchronized(listener) {
			super.onPause();
		}
	}

	@Override
	public void onResume() {
		synchronized(listener) {
			super.onResume();
		}
	}

	@Override
	public void onReady() {
		synchronized(listener) {
			super.onReady();
		}
	}

	@Override
	public void onIdle() {
		synchronized(listener) {
			super.onIdle();
		}
	}

	@Override
	public void onEvt(Object evt, Object value) {
		synchronized(listener) {
			super.onEvt(evt, value);
		}
	}

	@Override
	public void onErr(Throwable t) {
		synchronized(listener) {
			super.onErr(t);
		}
	}

	protected static class Coll extends ListListener {}
}
