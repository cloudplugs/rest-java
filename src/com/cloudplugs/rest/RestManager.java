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

import org.json.JSONObject;

import com.cloudplugs.util.Channel;
import com.cloudplugs.util.Str;
import com.cloudplugs.util.Timestamp;
import com.cloudplugs.util.Validate;

/**
 * @brief Class for handling remote requests with CloudPlugs server.
 *
 * An instance of this class can be obtained by calling {@link RestClient#getManager(Opts)}.
 * Most methods of this class send requests to the server and are named using the prefix <tt>exec</tt>.
 * Such methods are executed in an asynchronous way, that implies the invokation will return as soon as possible, usually
 * before sending the request over the network.
 * <br/><br/>
 * All the requests will be serially enqueued and sent (following the order of method calls) in a separated thread spooler,
 * transparent to the developer.
 * The last argument of each request method is an instance of the interface {@link RestCallback},
 * its method {@link RestCallback#on} will receive the results of the asynchronous execution: the produced {@link Request}
 * and its {@link Response}.
 * The method {@link RestCallback#on} will be called by the underlying spooler and it will be executed in the thread of
 * the underlying spooler, keep it in mind because any invokation requires main thread execution (for example GUI update)
 * will fail if directly called from a {@link RestCallback#on} implementation.
 * <br/><br/>
 * The return value of all <tt>exec</tt> prefixed methods is an integer identifier for controlling the request execution flow.
 * For instance, you can call {@link RestBaseManager#cancel(int)} to cancel an enqueued request or you can
 * call {@link RestBaseManager#waitFor(int)} to wait for the completition of an enqueued request.<br/>
 * See {@link RestBaseManager} for additional details.
 */
public class RestManager extends RestBaseManager
{
	/** Event String used to notify any registered {@link com.cloudplugs.util.Listener} about a successful enroll. */
	public static final String EVT_ENROLL = "enroll";

	public static final String K_MODEL     = "model";
	public static final String K_HWID      = "hwid";
	public static final String K_PASS      = "pass";
	public static final String K_CTRL      = "ctrl";
	public static final String K_NAME      = "name";
	public static final String K_PROPS     = "props";
	public static final String K_DATA      = "data";
	public static final String K_OF        = "of";
	public static final String K_AT        = "at";
	public static final String K_BEFORE    = "before";
	public static final String K_AFTER     = "after";
	public static final String K_OFFSET    = "offset";
	public static final String K_LIMIT     = "limit";
	public static final String K_TTL       = "ttl";
	public static final String K_EXPIRE    = "expire_at";
	public static final String K_ID        = "id";
	public static final String K_AUTH      = "auth";
	public static final String K_STATUS    = "status";
	public static final String K_PERM      = "perm";
	public static final String K_LOCATION  = "location";

	public static final String LOCATION_LONGITUDE = "x";
	public static final String LOCATION_LATITUDE  = "y";
	public static final String LOCATION_ALTITUDE  = "z";
	public static final String LOCATION_ACCURACY  = "r";
	public static final String LOCATION_TIME      = "t";

	public static final String STATUS_OK         = "ok";
	public static final String STATUS_DISABLED   = "disabled";
	public static final String STATUS_REACTIVATE = "reactivate";

	protected static final String ACTION_DEVICE  = "device";
	protected static final String ACTION_DATA    = "data";
	protected static final String ACTION_CHANNEL = "channel";

	protected RestManager(RestSpooler spooler, Opts opts) {
		super(spooler, opts);
	}

	//---- enroll/unenroll

	/**
	 * Enqueue an asynchronous request for enrolling a controller.
	 * This is the a low level method you can directly set the body of the HTTP request.
	 * See {@link #execEnrollController(String, String, String, String, String, JSONObject, RestCallback)}
	 * for a more convenient way to enroll a controller.
	 * Device authentication credentials cannot be set before invoking this method.
	 * @param body the JSON body of the HTTP request to send
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 * @see #execControlDevice(String, RestCallback) to control a device without enrolling
	 */
	public int execEnrollController(String body, RestCallback cb) {
		wantNoDeviceAuth();
		Validate.body(body);
		return execPut(ACTION_DEVICE, null, body, makeEnrollCb(cb));
	}

	/**
	 * Enqueue an asynchronous request for enrolling a controller.
	 * Device authentication credentials cannot be set before invoking this method.
	 * @param model the model identifier of the device to control
	 * @param ctrl the serial number of the device to control
	 * @param pass the secret password for controlling the device
	 * @param hwid if not null, a unique String to identify this controller (if null, it will be automatically computed by the server)
	 * @param name if not null, the name of this controller
	 * @param props if not null, the additional properties (key-value pairs) of this controller
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException when having authentication credentials or IllegalArgumentException for argument validation error
	 * @see #execControlDevice(String, String, String, RestCallback) to control a device without enrolling
	 */
	public int execEnrollController(String model, String ctrl, String pass, String hwid, String name, JSONObject props, RestCallback cb) {
		Validate.modelId(model);
		Validate.hwid(ctrl, "ctrl");
		Validate.pass(pass);
		if(hwid != null) Validate.hwid(hwid);
		return execEnrollController(bodyGen(
			K_MODEL, model, K_CTRL, ctrl, K_PASS, pass, K_HWID, hwid, K_NAME, name, K_PROPS, props), cb);
	}

	/**
	 * Enqueue an asynchronous request for enrolling a production thing.
	 * This is the a low level method you can directly set the body of the HTTP request.
	 * See {@link #execEnrollProduct(String, String, String, JSONObject, RestCallback)}
	 * for a more convenient way to enroll a production thing.
	 * Device authentication credentials cannot be set before invoking this method.
	 * @param body the JSON body of the HTTP request to send
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execEnrollProduct(String body, RestCallback cb) {
		wantNoDeviceAuth();
		Validate.body(body);
		return execPost(ACTION_DEVICE, null, body, makeEnrollCb(cb));
	}

	/**
	 * Enqueue an asynchronous request for enrolling a production thing.
	 * Device authentication credentials cannot be set before invoking this method.
	 * @param model the model identifier of this device
	 * @param hwid the serial number of this device
	 * @param pass the secret password for enrolling this device
	 * @param props if not null, the additional properties (key-value pairs) of this device as an instance of {@link org.json.JSONObject}
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException when having authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execEnrollProduct(String model, String hwid, String pass, JSONObject props, RestCallback cb) {
		Validate.modelId(model);
		Validate.pass(pass);
		Validate.hwid(hwid);
		return execEnrollProduct(bodyGen(K_MODEL, model, K_HWID, hwid, K_PASS, pass, K_PROPS, props), cb);
	}

	/**
	 * Enqueue an asynchronous request for enrolling a new prototype.
	 * This is the a low level method you can directly set the body of the HTTP request.
	 * See {@link #execEnrollPrototype(String, String, String, JSONObject, JSONObject, RestCallback)}
	 * for a more convenient way to enroll a production thing.
	 * Email authentication credentials must be set before invoking this method.
	 * @param body the JSON body of the HTTP request to send
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execEnrollPrototype(String body, RestCallback cb) {
		wantEmailAuth();
		Validate.body(body);
		return execPost(ACTION_DEVICE, null, body, makeEnrollCb(cb));
	}

	/**
	 * Enqueue an asynchronous request for enrolling a new prototype.
	 * Email authentication credentials must be set before invoking this method.
	 * @param pass for setting the authentication password of the new prototype
	 * @param name a unique String name for this prototype
	 * @param hwid if not null, a unique String to identify this device (if null, it will be automatically computed by the server)
	 * @param props if not null, the additional properties (key-value pairs) of this device as an instance of {@link org.json.JSONObject}
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execEnrollPrototype(String pass, String name, String hwid, JSONObject perm, JSONObject props, RestCallback cb) {
		Validate.pass(pass);
		if(hwid != null) Validate.hwid(hwid);
		if(name != null) Validate.name(name);
		if(perm != null) Validate.perm(perm);
		return execEnrollPrototype(bodyGen(K_PASS, pass, K_NAME, name, K_HWID, hwid, K_PERM, perm, K_PROPS, props),  cb);
	}

	/**
	 * Unenroll this device and remove all data stored in the cloud and related to this device.
	 * Device authentication credentials must be set before invoking this method.
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials
	 */
	public int execUnenroll(RestCallback cb) {
		wantDeviceAuth();
		return execDelete(ACTION_DEVICE, null, '"'+opts.getAuthId()+'"', cb);
	}

	/**
	 * Unenroll the specified device and remove all data stored in the cloud and related to that device.
	 * Email authentication credentials must be set before invoking this method.
	 * @param idPlug the PlugID identifies the device to unenroll
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execUnenroll(String idPlug, RestCallback cb) {
		wantEmailAuth();
		Validate.devIdCsv(idPlug);
		return execDelete(ACTION_DEVICE, null, idPlug, cb);
	}

	/**
	 * Unenroll the specified devices and remove all data stored in the cloud and related to those devices.
	 * Email authentication credentials must be set before invoking this method.
	 * @param idPlugs the PlugIDs identify the devices to unenroll
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execUnenroll(String[] idPlugs, RestCallback cb) {
		wantEmailAuth();
		Validate.devIds(idPlugs);
		return execDelete(ACTION_DEVICE, null, bodyGen((Object)idPlugs), cb);
	}

	/**
	 * Enqueue an asynchronous request for asking grants to control another device.
	 * This is the a low level method you can directly set the body of the HTTP request.
	 * See {@link #execControlDevice(String, String, String, RestCallback)}
	 * for a more convenient way to enroll a controller.
	 * Device authentication credentials must be set before invoking this method.
	 * @param body the JSON body of the HTTP request to send
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 * @see #execEnrollController(String, RestCallback) to enroll a controller
	 */
	public int execControlDevice(String body, RestCallback cb) {
		wantDeviceAuth();
		Validate.body(body);
		return execPut(ACTION_DEVICE, null, body, makeEnrollCb(cb));
	}

	/**
	 * Enqueue an asynchronous request for asking grants to control another device.
	 * Device authentication credentials must be set before invoking this method.
	 * @param model the model identifier of the device to control
	 * @param ctrl the serial number of the device to control
	 * @param pass the secret password for controlling the device
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 * @see #execEnrollController(String, String, String, String, String, JSONObject, RestCallback) for enrolling a controller
	 */
	public int execControlDevice(String model, String ctrl, String pass, RestCallback cb) {
		Validate.modelId(model);
		Validate.devId(ctrl);
		Validate.pass(pass);
		return execControlDevice(bodyGen(K_MODEL, model, K_CTRL, ctrl, K_PASS, pass), cb);
	}

	/**
	 * Enqueue an asynchronous request for releasing the control of a device.
	 * Successful responses require the control of the device was already been grant.
	 * Device authentication credentials must be set before invoking this method.
	 * @param idPlug the PlugID identifies the device to release control; you can pass a CSV of PlugIDs to release the control of more devices at the same time
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execUncontrolDevice(String idPlug, RestCallback cb) {
		wantDeviceAuth();
		String body;
		if(idPlug != null) {
			Validate.devIdCsv(idPlug);
			body = '"'+ idPlug +'"';
		} else {
			body = "null";
		}
		return execDelete(ACTION_DEVICE, opts.getAuthId(), body, cb);
	}

	/**
	 * Enqueue an asynchronous request for releasing the control of one or more devices.
	 * Successful responses require the control of the devices was already been grant.
	 * Device authentication credentials must be set before invoking this method.
	 * @param idPlugs one or more PlugIDs identify the devices to release control
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execUncontrolDevice(String[] idPlugs, RestCallback cb) {
		wantDeviceAuth();
		String body;
		if(idPlugs != null) {
			Validate.devIds(idPlugs);
			body = '"'+ Str.csv(idPlugs) +'"';
		} else {
			body = "null";
		}
		return execDelete(ACTION_DEVICE, opts.getAuthId(), body, cb);
	}

	//---- device crud

	/**
	 * Enqueue an asynchronous request for getting all the information about a specific device.
	 * The response could fail if the authentication credentials don't have enough grants to read such information.
	 * Authentication credentials must be set before invoking this method.
	 * @param idPlug the PlugID identifies the device to read
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execGetDevice(String idPlug, RestCallback cb) {
		wantAuth();
		Validate.devId(idPlug);
		return execGet(ACTION_DEVICE, idPlug, cb);
	}

	/**
	 * Enqueue an asynchronous request for getting all the information about this device.
	 * Device authentication credentials must be set before invoking this method.
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execGetDevice(RestCallback cb) {
		wantDeviceAuth();
		return execGetDevice(opts.getAuthId(), cb);
	}

	/**
	 * Enqueue an asynchronous request for setting information about this device.
	 * This is the a low level method you can directly set the body of the HTTP request.
	 * See {@link #execSetDevice(String, JSONObject, RestCallback)}
	 * for a more convenient way to set the information of this device.
	 * Device authentication credentials must be set before invoking this method.
	 * @param body the JSON body of the HTTP request to send
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execSetDevice(String body, RestCallback cb) {
		wantDeviceAuth();
		return execSetDevice(opts.getAuthId(), body, cb);
	}

	/**
	 * Enqueue an asynchronous request for setting information about a specific device.
	 * This is the a low level method you can directly set the body of the HTTP request.
	 * See {@link #execSetDevice(String, String, JSONObject, String, JSONObject, RestCallback)}
	 * for a more convenient way to set the information of this device.
	 * The response could fail if the authentication credentials don't have enough grants to write such information.
	 * Authentication credentials must be set before invoking this method.
	 * @param idPlug the PlugID identifies the device to modify
	 * @param body the JSON body of the HTTP request to send
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execSetDevice(String idPlug, String body, RestCallback cb) {
		wantAuth();
		Validate.devId(idPlug);
		Validate.body(body);
		return execPatch(ACTION_DEVICE, idPlug, body, cb);
	}

	/**
	 * Enqueue an asynchronous request for setting information of this device.
	 * Device authentication credentials must be set before invoking this method.
	 * @param name if not null, the new name of this device
	 * @param props if not null, the additional properties (key-value pairs) to set for this device
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execSetDevice(String name, JSONObject props, RestCallback cb) {
		if(name != null) Validate.name(name);
		return execSetDevice(bodyGen(K_NAME, name, K_PROPS, props), cb);
	}

	/**
	 * Enqueue an asynchronous request for setting information of a specific device.
	 * The response could fail if the authentication credentials don't have enough grants to write such information.
	 * Authentication credentials must be set before invoking this method.
	 * @param idPlug the PlugID identifies the device to modify
	 * @param name if not null, the new name of this device
	 * @param props if not null, the additional properties (key-value pairs) to set for this device
	 * @param status if not null, the new status of the device, one of {@link #STATUS_OK}, {@link #STATUS_DISABLED} or {@link #STATUS_REACTIVATE}
	 *               (the last one won't work on prototypes and controllers, but only on production things)
	 * @param perm if not null, a JSON of the new permission object to assign to the device
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execSetDevice(String idPlug, String name, JSONObject props, String status, JSONObject perm, RestCallback cb) {
		if(name   != null) Validate.name(name);
		if(status != null) Validate.status(status);
		if(perm   != null) Validate.perm(perm);
		return execSetDevice(idPlug, bodyGen(K_NAME, name, K_STATUS, status, K_PERM, perm, K_PROPS, props), cb);
	}

	/**
	 * Enqueue an asynchronous request for getting the value of a specific additional property of this device.
	 * Device authentication credentials must be set before invoking this method.
	 * @param prop the name of the additional property to get, if null the entire additional properties JSON object will be got
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execGetDeviceProp(String prop, RestCallback cb) {
		wantDeviceAuth();
		return execGetDeviceProp(opts.getAuthId(), prop, cb);
	}

	/**
	 * Enqueue an asynchronous request for getting the value of a specific additional property of the given device.
	 * The response could fail if the authentication credentials don't have enough grants to read such property.
	 * Authentication credentials must be set before invoking this method.
	 * @param idPlug the PlugID identifies the device to read
	 * @param prop the name of the additional property to get, if null the entire additional properties JSON object will be got
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execGetDeviceProp(String idPlug, String prop, RestCallback cb) {
		wantAuth();
		Validate.devId(idPlug);
		return execGet(ACTION_DEVICE, idPlug + '/' + (prop == null ? "" : prop), cb);
	}

	/**
	 * Enqueue an asynchronous request for setting the value of one or more additional properties of this device.
	 * Device authentication credentials must be set before invoking this method.
	 * @param prop the name of the additional property to set, if null then <tt>value</tt> will contain a JSON object of all additional properties to set
	 * @param value the JSON value to set for the property <tt>prop</tt> or if <tt>prop</tt> is null it contains the JSON object of all additional properties to set
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execSetDeviceProp(String prop, String value, RestCallback cb) {
		wantDeviceAuth();
		return execSetDeviceProp(opts.getAuthId(), prop, value, cb);
	}

	/**
	 * Enqueue an asynchronous request for setting the value of one or more additional properties of the given device.
	 * The response could fail if the authentication credentials don't have enough grants to write such properties.
	 * Authentication credentials must be set before invoking this method.
	 * @param idPlug the PlugID identifies the device to modify
	 * @param prop the name of the additional property to set, if null then <tt>value</tt> will contain a JSON object of all additional properties to set
	 * @param value the JSON value to set for the property <tt>prop</tt> or if <tt>prop</tt> is null it contains the JSON object of all additional properties to set
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execSetDeviceProp(String idPlug, String prop, String value, RestCallback cb) {
		wantAuth();
		Validate.devId(idPlug);
		Validate.body(value);
		return execPatch(ACTION_DEVICE, idPlug + '/' + (prop == null ? "" : prop), value, cb);
	}

	/**
	 * Enqueue an asynchronous request for removing a specific additional property of the given device.
	 * The response could fail if the authentication credentials don't have enough grants to remove the property.
	 * Authentication credentials must be set before invoking this method.
	 * @param idPlug the PlugID identifies the device to modify
	 * @param prop the name of the additional property to remove
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execRemoveDeviceProp(String idPlug, String prop, RestCallback cb) {
		wantAuth();
		Validate.devId(idPlug);
		Validate.prop(prop);
		return execDelete(ACTION_DEVICE, idPlug + '/' + prop, null, cb);
	}

	/**
	 * Enqueue an asynchronous request for removing a specific additional property of this device.
	 * Device authentication credentials must be set before invoking this method.
	 * @param prop the name of the additional property to remove
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execRemoveDeviceProp(String prop, RestCallback cb) {
		wantDeviceAuth();
		return execRemoveDeviceProp(opts.getAuthId(), prop, cb);
	}

	/**
	 * Enqueue an asynchronous request for getting the value of the location additional property of this device.
	 * Device authentication credentials must be set before invoking this method.
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execGetDeviceLocation(RestCallback cb) {
		wantDeviceAuth();
		return execGetDeviceLocation(opts.getAuthId(), cb);
	}

	/**
	 * Enqueue an asynchronous request for getting the value of the location additional property of the given device.
	 * The response could fail if the authentication credentials don't have enough grants to read the location.
	 * Authentication credentials must be set before invoking this method.
	 * @param idPlug the PlugID identifies the device to read
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execGetDeviceLocation(String idPlug, RestCallback cb) {
		return execGetDeviceProp(idPlug, K_LOCATION, cb);
	}

	/**
	 * Enqueue an asynchronous request for setting the value of the location additional property of this device.
	 * Device authentication credentials must be set before invoking this method.
	 * @param lon the longitude from -180 to 180, it cannot be null
	 * @param lat the latitude from -90 to 90, it cannot be null
	 * @param alt the altitude in meters over the sea or null if this location has no altitude
	 * @param accuracy the location accuracy in meters or null if this location has no accuracy
	 * @param time if not null, the timestamp (Number, String or java.util.Date) this location has been measured
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execSetDeviceLocation(Number lon, Number lat, Number alt, Number accuracy, Object time, RestCallback cb) {
		wantDeviceAuth();
		return execSetDeviceLocation(opts.getAuthId(), lon, lat, alt, accuracy, time, cb);
	}

	/**
	 * Enqueue an asynchronous request for setting the value of the <tt>location</tt> additional property of the given device.
	 * The response could fail if the authentication credentials don't have enough grants to write the location.
	 * Authentication credentials must be set before invoking this method.
	 * @param idPlug the PlugID identifies the device to modify
	 * @param lon the longitude from -180 to 180, it cannot be null
	 * @param lat the latitude from -90 to 90, it cannot be null
	 * @param alt the altitude in meters over the sea or null if this location has no altitude
	 * @param accuracy the location accuracy in meters or null if this location has no accuracy
	 * @param time if not null, the timestamp (Number, String or java.util.Date) this location has been measured
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execSetDeviceLocation(String idPlug, Number lon, Number lat, Number alt, Number accuracy, Object time, RestCallback cb) {
		double v = lon==null ? 200 : lon.doubleValue();
		if(v<-180 || v>180) throw new IllegalArgumentException("invalid longitude");
		v = lat==null ? 200 : lat.doubleValue();
		if(v<-90  || v>90 ) throw new IllegalArgumentException("invalid latitude" );
		time = time==null ? System.currentTimeMillis() : ts(time, LOCATION_TIME);
		return execSetDeviceLocation(idPlug, bodyGen(LOCATION_TIME, time,
			LOCATION_LONGITUDE, lon, LOCATION_LATITUDE, lat, LOCATION_ALTITUDE, alt, LOCATION_ACCURACY, accuracy), cb);
	}

	/**
	 * Enqueue an asynchronous request for setting the value of the <tt>location</tt> additional property of the given device.
	 * See {@link #execSetDeviceLocation(String, Number, Number, Number, Number, Object, RestCallback)}
	 * for a more convenient way to set the location.
	 * The response could fail if the authentication credentials don't have enough grants to write the location.
	 * Authentication credentials must be set before invoking this method.
	 * @param idPlug the PlugID identifies the device to modify
	 * @param location the JSON object of the location to set
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execSetDeviceLocation(String idPlug, String location, RestCallback cb) {
		return execSetDeviceProp(idPlug, K_LOCATION, location, cb);
	}

	/**
	 * Enqueue an asynchronous request for setting the value of the <tt>location</tt> additional property of this device.
	 * See {@link #execSetDeviceLocation(Number, Number, Number, Number, Object, RestCallback)}
	 * for a more convenient way to set the location.
	 * Device authentication credentials must be set before invoking this method.
	 * @param location the JSON object of the location to set
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execSetDeviceLocation(String location, RestCallback cb) {
		return execSetDeviceProp(K_LOCATION, location, cb);
	}

	/**
	 * Enqueue an asynchronous request for removing the <tt>location</tt> additional property of this device.
	 * Device authentication credentials must be set before invoking this method.
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execRemoveDeviceLocation(RestCallback cb) {
		return execRemoveDeviceProp(K_LOCATION, cb);
	}

	/**
	 * Enqueue an asynchronous request for removing the <tt>location</tt> additional property of the given device.
	 * The response could fail if the authentication credentials don't have enough grants to remove the property.
	 * Authentication credentials must be set before invoking this method.
	 * @param idPlug the PlugID identifies the device to modify
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execRemoveDeviceLocation(String idPlug, RestCallback cb) {
		return execRemoveDeviceProp(idPlug, K_LOCATION, cb);
	}

	//---- publish/retrieve data

	/**
	 * Enqueue an asynchronous request for getting all existing channel names match with the given mask and such that
	 * all conditions in the query parameters are satisfied.
	 * See {@link #execGetChannels(String, Object, String, int, int, RestCallback)}
	 * and {@link #execGetChannels(String, Object, Object, String, int, int, RestCallback)}
	 * for more convenient ways to get the channel names.
	 * Authentication credentials must be set before invoking this method.
	 * @param channelMask the channel mask used to filter the results
	 * @param params the query parameters with the conditions or null if no condition should be applied
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execGetChannels(String channelMask, String params, RestCallback cb) {
		wantAuth();
		Validate.channelMask(channelMask);
		return execGet(ACTION_CHANNEL, pathQuery(Channel.toUrl(channelMask), params), cb);
	}

	/**
	 * Enqueue an asynchronous request for getting all existing channel names match with the given mask.
	 * Authentication credentials must be set before invoking this method.
	 * @param channelMask the channel mask used to filter the results
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execGetChannels(String channelMask, RestCallback cb) {
		return execGetChannels(channelMask, null, cb);
	}

	/**
	 * Enqueue an asynchronous request for getting all existing channel names match with the given mask and such that
	 * all specified conditions in the other arguments are satified.
	 * Authentication credentials must be set before invoking this method.
	 * @param channelMask the channel mask used to filter the results
	 * @param at if not null, timestamp: the channels must contain data published on specified timestamp (Number, String or java.util.Date)
	 * @param of if not null, PlugIDs CSV: the channels must contain data published by one of the specified PlugIDs
	 * @param offset how many result channels to skip in the response, 0 to avoid skipping
	 * @param limit maximum number of channels to include in the response, 0 to get as many as possible
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execGetChannels(String channelMask, Object at, String of, int offset, int limit, RestCallback cb) {
		if(of != null) Validate.plugIdCsv(of);
		if(offset < 0) offset = 0;
		if(limit  < 0) limit  = 0;
		return execGetChannels(channelMask, queryGen(
			K_AT, ts(at, K_AT), K_OF, of, K_OFFSET, offset, K_LIMIT, limit), cb);
	}

	/**
	 * Enqueue an asynchronous request for getting all existing channel names match with the given mask and such that
	 * all specified conditions in the other arguments are satified.
	 * Authentication credentials must be set before invoking this method.
	 * @param channelMask the channel mask used to filter the results
	 * @param at if not null, timestamp: the channels must contain data published on specified timestamp (Number, String or java.util.Date)
	 * @param of if not null, PlugIDs CSV: the channels must contain data published by one of the specified PlugIDs
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execGetChannels(String channelMask, Object at, String of, RestCallback cb) {
		return execGetChannels(channelMask, at, of, 0, 0, cb);
	}

	/**
	 * Enqueue an asynchronous request for getting all existing channel names match with the given mask and such that
	 * all specified conditions in the other arguments are satified.
	 * Authentication credentials must be set before invoking this method.
	 * @param channelMask the channel mask used to filter the results
	 * @param before if not null, timestamp or data ID: the channels must contain data published before the timestamp (Number, String or java.util.Date) or before the data ID
	 * @param after if not null, timestamp or data ID: the channels must contain data published after the timestamp (Number, String or java.util.Date) or after the data ID
	 * @param of if not null, PlugIDs CSV: the channels must contain data published by one of the specified PlugIDs
	 * @param offset how many result channels to skip in the response, 0 to avoid skipping
	 * @param limit maximum number of channels to include in the response, 0 to get as many as possible
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execGetChannels(String channelMask, Object before, Object after, String of, int offset, int limit, RestCallback cb) {
		if(of != null) Validate.plugIdCsv(of);
		if(offset < 0) offset = 0;
		if(limit  < 0) limit  = 0;
		return execGetChannels(channelMask, queryGen(
			K_BEFORE, tso(before, K_BEFORE), K_AFTER, tso(after, K_AFTER),
			K_OF, of, K_OFFSET, offset, K_LIMIT, limit), cb);
	}

	/**
	 * Enqueue an asynchronous request for getting all existing channel names match with the given mask and such that
	 * all specified conditions in the other arguments are satified.
	 * Authentication credentials must be set before invoking this method.
	 * @param channelMask the channel mask used to filter the results
	 * @param before if not null, timestamp or data ID: the channels must contain data published before the timestamp (Number, String or java.util.Date) or before the data ID
	 * @param after if not null, timestamp or data ID: the channels must contain data published after the timestamp (Number, String or java.util.Date) or after the data ID
	 * @param of if not null, PlugIDs CSV: the channels must contain data published by one of the specified PlugIDs
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execGetChannels(String channelMask, Object before, Object after, String of, RestCallback cb) {
		return execGetChannels(channelMask, before, after, of, 0, 0, cb);
	}

	/**
	 * Enqueue an asynchronous request for retrieving already published data.
	 * Authentication credentials must be set before invoking this method.
	 * @param channelMask the channel mask used to filter which data should be retrieved
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws IllegalArgumentException if an argument is not valid.
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execRetrieveData(String channelMask, RestCallback cb) {
		return execRetrieveData(channelMask, null, cb);
	}

	/**
	 * Enqueue an asynchronous request for retrieving already published data.
	 * This is the a low level method you can specify directly the URL query of the request.
	 * See {@link #execRetrieveData(String, RestCallback)},
	 * {@link #execRetrieveData(String, Object, String, int, int, RestCallback)}
	 * and {@link #execRetrieveData(String, Object, Object, String, int, int, RestCallback)}
	 * for more convenient ways to retrieve published data.
	 * Authentication credentials must be set before invoking this method.
	 * @param channelMask the channel mask used to filter which data should be retrieved
	 * @param params if not null the parameters string of the query url
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execRetrieveData(String channelMask, String params, RestCallback cb) {
		wantAuth();
		Validate.channelMask(channelMask);
		return execGet(ACTION_DATA, pathQuery(Channel.toUrl(channelMask), params), cb);
	}

	/**
	 * Enqueue an asynchronous request for retrieving already published data.
	 * Optionally filter the data by Plug-IDs of data publishers and/or by the timestamp <tt>at</tt>at when data has been published.
	 * Authentication credentials must be set before invoking this method.
	 * @param channelMask the channel mask used to filter which data should be retrieved
	 * @param at if not null, the timestamp (Number, String or java.util.Date) the data has been published
	 * @param of if not null, the CSV string of Plug-IDs published the data to retrieve
	 * @param offset if greater than zero, the resulting response will contain values after the offset-th one
	 * @param limit if greater than zero, the resulting response will contain at most
	 * @param cb if not null, the callback will receive the Request and its Response
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execRetrieveData(String channelMask, Object at, String of, int offset, int limit, RestCallback cb) {
		if(of != null) Validate.plugIdCsv(of);
		if(offset < 0) offset = 0;
		if(limit  < 0) limit  = 0;
		return execRetrieveData(channelMask, queryGen(
			K_AT, ts(at, K_AT), K_OF, of, K_OFFSET, offset, K_LIMIT, limit), cb);
	}

	/**
	 * Enqueue an asynchronous request for retrieving already published data.
	 * Optionally filter the data to retrieve by Plug-IDs of data publishers and/or by choosing specific intervals with <tt>before</tt> <tt>after</tt>after.
	 * Authentication credentials must be set before invoking this method.
	 * @param channelMask the channel mask used to filter which data should be retrieved
	 * @param before if not null, the most recent timestamp (Number, String or java.util.Date) of the data to retrieve or a String contains the published data ID before which retrieve the data
	 * @param after if not null, the minimum timestamp (Number, String or java.util.Date) of the data to retrieve or a String contains the published data ID after which retrieve the data
	 * @param of if not null, the CSV string of Plug-IDs published the data to retrieve
	 * @param offset if greater than zero, the resulting response will contain values after the offset-th one
	 * @param limit if greater than zero, the resulting response will contain at most
	 * @param cb if not null, the callback will receive the {@link Request} and its {@link Response}
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execRetrieveData(String channelMask, Object before, Object after, String of, int offset, int limit, RestCallback cb) {
		if(of != null) Validate.plugIdCsv(of);
		if(offset < 0) offset = 0;
		if(limit  < 0) limit  = 0;
		return execRetrieveData(channelMask, queryGen(
			K_BEFORE, tso(before, K_BEFORE), K_AFTER, tso(after, K_AFTER),
			K_OF, of, K_OFFSET, offset, K_LIMIT, limit), cb);
	}

	/**
	 * Enqueue an asynchronous request for publishing data.
	 * This is the a low level method you can specify directly the body of the request.
	 * See {@link #execPublishData(String, Object, Object, String, Object, RestCallback)},
	 * {@link #execPublishData(String, Object, Object, String, RestCallback)},
	 * {@link #execPublishData(String, Object, Object, Object, RestCallback)}
	 * and {@link #execPublishData(String, Object, Object, RestCallback)}
	 * for more convenient ways to publish data.
	 * Authentication credentials must be set before invoking this method.
	 * @param channelName the channel name to publish data to
	 * @param body the JSON body of the HTTP request to send
	 * @param cb if not null, the callback will receive the {@link Request} and its {@link Response}
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execPublishData(String channelName, String body, RestCallback cb) {
		wantAuth();
		if(channelName != null) Validate.channelName(channelName);
		Validate.body(body);
		return execPut(ACTION_DATA, channelName, body, cb);
	}

	/**
	 * Enqueue an asynchronous request for publishing data.
	 * Authentication credentials must be set before invoking this method.
	 * @param channelName the channel name to publish data to
	 * @param data the JSON data to publish
	 * @param at the timestamp (Number, String or java.util.Date) of the data, if null the server will automatically set this value as the current date
	 * @param of the Plug-ID string of the publisher of the data; null means this device
	 * @param ttlOrExpire if not null, an expire timestamp (Number, String or java.util.Date) to set when this data will be automatically removed or a time-to-live of the data in seconds
	 * @param cb if not null, the callback will receive the {@link Request} and its {@link Response}
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execPublishData(String channelName, Object data, Object at, String of, Object ttlOrExpire, RestCallback cb) {
		return execPublishData(channelName, null, data, at, of, ttlOrExpire, cb);
	}

	/**
	 * Enqueue an asynchronous request for publishing data.
	 * Authentication credentials must be set before invoking this method.
	 * @param channelName the channel name to publish data to
	 * @param data the JSON data to publish
	 * @param at the timestamp (Number, String or java.util.Date) of the data, if null the server will automatically set this value as the current date
	 * @param ttlOrExpire if not null, an expire timestamp (Number, String or java.util.Date) to set when this data will be automatically removed or a time-to-live of the data in seconds
	 * @param cb if not null, the callback will receive the {@link Request} and its {@link Response}
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execPublishData(String channelName, Object data, Object at, Object ttlOrExpire, RestCallback cb) {
		return execPublishData(channelName, null, data, at, null, ttlOrExpire, cb);
	}

	/**
	 * Enqueue an asynchronous request for publishing new data or changing an already published data.
	 * The response could fail if the authentication credentials don't have enough grants to complete the publication.
	 * Authentication credentials must be set before invoking this method.
	 * @param channelName the channel name to publish data to
	 * @param id null for publishing new data, otherwise the id of a previously published data to modify
	 * @param data the JSON data to publish
	 * @param at the timestamp (Number, String or java.util.Date) of the data, if null the server will automatically set this value as the current date
	 * @param of the Plug-ID string of the publisher of the data; null means this device
	 * @param ttlOrExpire if not null, an expire timestamp (Number, String or java.util.Date) to set when this data will be automatically removed or a time-to-live of the data in seconds
	 * @param cb if not null, the callback will receive the {@link Request} and its {@link Response}
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execPublishData(String channelName, String id, Object data, Object at, String of, Object ttlOrExpire, RestCallback cb) {
		if(channelName == null) throw new IllegalArgumentException("null channel name");
		if(of != null) Validate.plugId(of);
		Object[] exp = toExpireKV(ttlOrExpire);
		return execPublishData(channelName, bodyGen(K_ID, id, K_DATA, data, K_AT, ts(at, K_AT), K_OF, of, exp[0], exp[1]), cb);
	}

	/**
	 * Enqueue an asynchronous request for publishing new data or changing an already published data.
	 * The response could fail if the authentication credentials don't have enough grants to complete the publication.
	 * Authentication credentials must be set before invoking this method.
	 * @param channelName the channel name to publish data to
	 * @param id null for publishing new data, otherwise the id of a previously published data to modify
	 * @param data the JSON data to publish
	 * @param at the timestamp (Number, String or java.util.Date) of the data, if null the server will automatically set this value as the current date
	 * @param ttlOrExpire if not null, an expire timestamp (Number, String or java.util.Date) to set when this data will be automatically removed or a time-to-live of the data in seconds
	 * @param cb if not null, the callback will receive the {@link Request} and its {@link Response}
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execPublishData(String channelName, String id, Object data, Object at, Object ttlOrExpire, RestCallback cb) {
		return execPublishData(channelName, id, data, at, null, ttlOrExpire, cb);
	}

	/**
	 * Enqueue an asynchronous request for publishing data.
	 * Authentication credentials must be set before invoking this method.
	 * @param channelName the channel name to publish data to
	 * @param data the JSON data to publish
	 * @param at the timestamp (Number, String or java.util.Date) of the data, if null the server will automatically set this value as the current date
	 * @param of the Plug-ID string of the publisher of the data; null means this device
	 * @param cb if not null, the callback will receive the {@link Request} and its {@link Response}
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execPublishData(String channelName, Object data, Object at, String of, RestCallback cb) {
		return execPublishData(channelName, data, at, of, null, cb);
	}

	/**
	 * Enqueue an asynchronous request for publishing data.
	 * Authentication credentials must be set before invoking this method.
	 * @param channelName the channel name to publish data to
	 * @param data the JSON data to publish
	 * @param at the timestamp (Number, String or java.util.Date) of the data, if null the server will automatically set this value as the current date
	 * @param cb if not null, the callback will receive the {@link Request} and its {@link Response}
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execPublishData(String channelName, Object data, Object at, RestCallback cb) {
		return execPublishData(channelName, data, at, null, null, cb);
	}

	/**
	 * Enqueue an asynchronous request for removing already published data.
	 * This is the a low level method you can specify directly the body of the request.
	 * See {@link #execRemoveData(String[], RestCallback)},
	 * {@link #execRemoveData(String, Object, Object, String, RestCallback)}
	 * and {@link #execRemoveData(String, Object, String, RestCallback)}
	 * for more convenient ways to remove data.
	 * The response could fail if the authentication credentials don't have enough grants to complete the operation.
	 * Authentication credentials must be set before invoking this method.
	 * @param channelMask the channel mask such that all data contained in it will be removed
	 * @param body the JSON body of the HTTP request
	 * @param cb if not null, the callback will receive the {@link Request} and its {@link Response}
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execRemoveData(String channelMask, String body, RestCallback cb) {
		wantAuth();
		Validate.body(body);
		if(channelMask != null) Validate.channelMask(channelMask);
		return execDelete(ACTION_DATA, channelMask, body, cb);
	}

	/**
	 * Enqueue an asynchronous request for removing already published data.
	 * The response could fail if the authentication credentials don't have enough grants to complete the operation.
	 * Authentication credentials must be set before invoking this method.
	 * @param channelMask the channel mask such that all data contained in it will be removed
	 * @param at if not null, remove only data published at this timestamp (Number, String or java.util.Date)
	 * @param of if not null, remove only data published by this PlugID or CSV of Plug-IDs
	 * @param cb if not null, the callback will receive the {@link Request} and its {@link Response}
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execRemoveData(String channelMask, Object at, String of, RestCallback cb) {
		if(of != null) Validate.plugIdCsv(of);
		return execRemoveData(channelMask, bodyGen(K_AT, tso(at, K_AT), K_OF, of), cb);
	}

	/**
	 * Enqueue an asynchronous request for removing already published data.
	 * The response could fail if the authentication credentials don't have enough grants to complete the operation.
	 * Authentication credentials must be set before invoking this method.
	 * @param channelMask the channel mask such that all data contained in it will be removed
	 * @param before if not null, remove only data published before this timestamp (Number, String or java.util.Date)
	 * @param after if not null, remove only data published after this timestamp (Number, String or java.util.Date)
	 * @param of if not null, remove only data published by this PlugID or CSV of Plug-IDs
	 * @param cb if not null, the callback will receive the {@link Request} and its {@link Response}
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execRemoveData(String channelMask, Object before, Object after, String of, RestCallback cb) {
		if(of != null) Validate.plugIdCsv(of);
		return execRemoveData(channelMask, bodyGen(
			K_BEFORE, tso(before, K_BEFORE), K_AFTER, tso(after, K_AFTER), K_OF, of), cb);
	}

	/**
	 * Enqueue an asynchronous request for removing already published data.
	 * The response could fail if the authentication credentials don't have enough grants to complete the operation.
	 * Authentication credentials must be set before invoking this method.
	 * @param ids array of all data ID to remove
	 * @param cb if not null, the callback will receive the {@link Request} and its {@link Response}
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execRemoveData(String[] ids, RestCallback cb) {
		Validate.oids(ids);
		return execRemoveData(null, bodyGen(K_ID, ids.length==1 ? ids[0] : ids), cb);
	}

	/**
	 * Enqueue an asynchronous request for removing already published data.
	 * The response could fail if the authentication credentials don't have enough grants to complete the operation.
	 * Authentication credentials must be set before invoking this method.
	 * @param id the data ID to remove
	 * @param cb if not null, the callback will receive the {@link Request} and its {@link Response}
	 * @return the identifier of this asynchronous execution
	 * @throws RestException for invalid authentication credentials or IllegalArgumentException for argument validation error
	 */
	public int execRemoveData(String id, RestCallback cb) {
		Validate.oid(id);
		return execRemoveData(null, bodyGen(K_ID, id), cb);
	}

	//---- protected api

	protected RestCallback makeEnrollCb(final RestCallback cb) {
		return new RestCallback() {
			@Override
			public void on(Request request, Response response) {
				if(cb != null) {
					try { cb.on(request, response); }
					catch(Exception e) { onErr(e); }
				}
				if(response.isSuccess()) {
					try {
						JSONObject resAuth = (JSONObject)response.getBodyAsJson();
						if(resAuth.has(K_ID)) {
							final String resId   = resAuth.getString(K_ID);
							final String resPass = resAuth.has(K_AUTH) ? resAuth.getString(K_AUTH) : null;
							if(resPass != null)
								if(!getOpts().hasAuth()) getOpts().setAuth(resId, resPass, false);
							runOnCb(cb, new Runnable() {
								@Override
								public void run() {
									onEvt(EVT_ENROLL, new Object[]{ resId, resPass });
								}
							});
						}
					} catch(Exception e) {
						onErr(e);
					}
				}
			}
		};
	}

	protected static Object[] toExpireKV(Object val) {
		return Timestamp.toKeyValue(K_TTL, K_EXPIRE, val);
	}
}
