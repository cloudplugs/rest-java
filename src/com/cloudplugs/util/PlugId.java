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

import java.util.regex.Pattern;

/**
 * @brief Tool class for easy PlugID validation.
 * This class is for internal usage.
 */
public final class PlugId
{
	/**
	 * @param idPlug the string to test
	 * @return true if the given string is a valid PlugID
	 */
	public static boolean is(String idPlug) {
		return idPlug!=null && rexPlug.matcher(idPlug).find();
	}

	/**
	 * @param idPlug the string to test
	 * @return true if the given string is a valid PlugID for a device
	 */
	public static boolean isDev(String idPlug) {
		return idPlug!=null && rexDev.matcher(idPlug).find();
	}

	/**
	 * @param idPlug the string to test
	 * @return true if the given string is a valid PlugID for a model
	 */
	public static boolean isModel(String idPlug) {
		return idPlug!=null && rexModel.matcher(idPlug).find();
	}

	/**
	 * @param id the string to test
	 * @return true if the given string is a valid ObjectID
	 */
	public static boolean isOid(String id) {
		return id!=null && rexOid.matcher(id).find();
	}

	/**
	 * @param idPlugCsv the string to test
	 * @return true if the given string is a valid CSV of one or more PlugID
	 */
	public static boolean isCsv(String idPlugCsv) {
		return idPlugCsv!=null && rexPlugCsv.matcher(idPlugCsv).find();
	}

	/**
	 * @param idPlugCsv the string to test
	 * @return true if the given string is a valid CSV of one or more PlugID of devices
	 */
	public static boolean isDevCsv(String idPlugCsv) {
		return idPlugCsv!=null && rexDevCsv.matcher(idPlugCsv).find();
	}

	/**
	 * @param idPlugCsv the string to test
	 * @return true if the given string is a valid CSV of one or more PlugID of models
	 */
	public static boolean isModelCsv(String idPlugCsv) {
		return idPlugCsv!=null && rexModelCsv.matcher(idPlugCsv).find();
	}

	/**
	 * @param idCsv the string to test
	 * @return true if the given string is a valid CSV of one or more ObjectID
	 */
	public static boolean isOidCsv(String idCsv) {
		return idCsv!=null && rexOidCsv.matcher(idCsv).find();
	}

	private PlugId() {}

	public static final String K_DEV = "dev";
	public static final String K_MOD = "mod";
	public static final String K_COM = "com";
	public static final String SEP   = "-";

	private static final String    OID_EXP = "[0-9a-fA-F]{24}";
	private static final String  DEVID_EXP = K_DEV + SEP + OID_EXP;
	private static final String  MODID_EXP = K_MOD + SEP + OID_EXP;
	private static final String PLUGID_EXP = "(?:"+ K_DEV +'|'+ K_MOD +'|'+ K_COM +')'+ SEP + OID_EXP;

	private static final Pattern rexOid   = Str.regexExact(OID_EXP);
	private static final Pattern rexDev   = Str.regexExact(DEVID_EXP);
	private static final Pattern rexModel = Str.regexExact(MODID_EXP);
	private static final Pattern rexPlug  = Str.regexExact(PLUGID_EXP);

	private static final Pattern rexOidCsv   = Str.regexCsv(OID_EXP);
	private static final Pattern rexDevCsv   = Str.regexCsv(DEVID_EXP);
	private static final Pattern rexModelCsv = Str.regexCsv(MODID_EXP);
	private static final Pattern rexPlugCsv  = Str.regexCsv(PLUGID_EXP);
}
