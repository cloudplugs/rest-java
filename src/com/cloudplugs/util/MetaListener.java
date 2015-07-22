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
 * @brief Convenient class encapsulates a {@link Listener} and acts just like the encapsulated one,
 * but it also invokes the {@link Listener#onErr(Throwable)} method if the encapsulated listener throws an exception.
 */
public class MetaListener implements Listener
{
	public MetaListener() {}

	public MetaListener(Listener l) {
		listener = l;
	}

	public Listener getListener() {
		return listener;
	}

	public void setListener(Listener l) {
		listener = l;
	}

	@Override
	public void onStart() {
		Listener l = listener;
		if(l == null) return;
		try { l.onStart(); }
		catch(Throwable t) { onErr(t); }
	}

	@Override
	public void onStop() {
		Listener l = listener;
		if(l == null) return;
		try { l.onStop(); }
		catch(Throwable t) { onErr(t); }
	}

	@Override
	public void onPause() {
		Listener l = listener;
		if(l == null) return;
		try { l.onPause(); }
		catch(Throwable t) { onErr(t); }
	}

	@Override
	public void onResume() {
		Listener l = listener;
		if(l == null) return;
		try { l.onResume(); }
		catch(Throwable t) { onErr(t); }
	}

	@Override
	public void onReady() {
		Listener l = listener;
		if(l == null) return;
		try { l.onReady(); }
		catch(Throwable t) { onErr(t); }
	}

	@Override
	public void onIdle() {
		Listener l = listener;
		if(l == null) return;
		try { l.onIdle(); }
		catch(Throwable t) { onErr(t); }
	}

	@Override
	public void onEvt(Object evt, Object value) {
		Listener l = listener;
		if(l == null) return;
		try { l.onEvt(evt, value); }
		catch(Throwable t) { onErr(t); }
	}

	@Override
	public void onErr(Throwable t) {
		Listener l = listener;
		if(l == null) {
			ErrHandler handler = ErrHandler.active;
			if(handler != null) handler.handleErr(t);
		} else try {
			l.onErr(t);
		} catch(Throwable t2) {
			ErrHandler handler = ErrHandler.active;
			if(handler != null) {
				handler.handleErr(t2);
				handler.handleErr(t);
			}
		}
	}

	protected Listener listener;
}
