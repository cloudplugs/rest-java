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

import java.util.concurrent.atomic.AtomicInteger;

/**
 * @brief A extension of {@link Spooler} with reference-counted start and stop.
 * This class is for internal usage.
 */
public class RefSpooler extends Spooler
{
	public RefSpooler() {}

	public RefSpooler(Listener listener) {
		super(listener);
	}

	public void ref() {
		if(refs.incrementAndGet() == 1)
			start();
	}

	public void unref() {
		if(refs.decrementAndGet() <= 0)
			stop();
	}

	private AtomicInteger refs = new AtomicInteger(0);
}
