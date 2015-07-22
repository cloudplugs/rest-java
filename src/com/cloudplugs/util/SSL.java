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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;


/**
 * @brief Tool class for easy manipulation of CA certificates over the SSL network.
 * The developer should avoid a direct usage of this class when connecting to an official CloudPlugs server.
 */
public final class SSL
{
	private SSL() {}

	/**
	 * Disable the peer and host verification when establishing any SSL connection, including HTTPS ones.
	 * This will allow any SSL connection also with untrusted peers in a easy way.
	 * The invocation of this method is discouraged due to security reasons, because it will permit Man-In-The-Middle attacks.
	 */
	public static void trustEveryone() {
		try {
			HttpsURLConnection.setDefaultHostnameVerifier(
				new HostnameVerifier() {
					@Override
					public boolean verify(String hostname, SSLSession session) {
						return true;
					}
				}
			);
			SSLContext ctx = SSLContext.getInstance(DEF_SSL_PROTO);
			ctx.init(null,
				new X509TrustManager[]{
					new X509TrustManager() {
						@Override
						public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
						@Override
						public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
						@Override
						public X509Certificate[] getAcceptedIssuers() {
							return null;
						}
					}
				},
				new SecureRandom()
			);
			HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
		} catch(Exception e) { // should never happen
			throw new RuntimeException(e);
		}
	}

	/**
	 * Allow safe SSL connections to the official CloudPlugs server.
	 * The developer does not need to invoke this method, it will be automatically invoked by other classes of the library.
	 * @throws KeyManagementException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public static void trustCloudPlugs() throws KeyManagementException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
		trustCA(getCA(DEF_CERT));
	}

	/**
	 * Allow safe SSL connections to any server is using the specified certificate.
	 * @param ca the certificate to trust
	 * @throws KeyManagementException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public static void trustCA(Certificate ca) throws KeyManagementException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
		HttpsURLConnection.setDefaultSSLSocketFactory(getSocketFactoryOf(ca));
	}

	/**
	 * Create a new instance of java.security.cert.Certificate by giving its type and its certificate encoded
	 * as a String.
	 * @param ca the certificate to trust
	 * @param type the type of certificate to generate
	 * @return the instance of a java.security.cert.Certificate
	 * @throws CertificateException
	 * @throws UnsupportedEncodingException
	 */
	public static Certificate getCA(String ca, String type) throws CertificateException, UnsupportedEncodingException {
		return getCA(ca.getBytes("UTF-8"), type);
	}

	/**
	 * Like {@link #getCA(String, String)}, but using the default type "X.509".
	 * @param ca the certificate to trust
	 * @return the instance of a java.security.cert.Certificate
	 * @throws CertificateException
	 * @throws UnsupportedEncodingException
	 */
	public static Certificate getCA(String ca) throws CertificateException, UnsupportedEncodingException {
		return getCA(ca, DEF_TYPE);
	}

	/**
	 * Create a new instance of java.security.cert.Certificate by giving its type and its certificate encoded
	 * as a byte array.
	 * @param ca the certificate to trust
	 * @param type the type of certificate to generate
	 * @return the instance of generated java.security.cert.Certificate
	 * @throws CertificateException
	 */
	public static Certificate getCA(byte[] ca, String type) throws CertificateException {
		return CertificateFactory.getInstance(type).generateCertificate(new ByteArrayInputStream(ca));
	}

	/**
	 * Like {@link #getCA(byte[], String)}, but using the default type "X.509".
	 * @param ca the certificate to trust
	 * @return the instance of generated java.security.cert.Certificate
	 * @throws CertificateException
	 */
	public static Certificate getCA(byte[] ca) throws CertificateException {
		return getCA(ca, DEF_TYPE);
	}

	/**
	 * Create a new instance of java.security.cert.Certificate by giving its type and its certificate encoded
	 * readable by the specified java.io.InputStream.
	 * @param ca the java.io.InputStream where reading the certificate to trust
	 * @param type the type of certificate to generate
	 * @return the instance of generated java.security.cert.Certificate
	 * @throws CertificateException
	 */
	public static Certificate getCA(InputStream ca, String type) throws CertificateException {
		return CertificateFactory.getInstance(type).generateCertificate(ca);
	}

	/**
	 * Like {@link #getCA(InputStream, String)}, but using the default type "X.509".
	 * @param ca the java.ioInputStream where reading the certificate to trust
	 * @return the instance of generated java.security.cert.Certificate
	 * @throws CertificateException
	 */
	public static Certificate getCA(InputStream ca) throws CertificateException {
		return getCA(ca, DEF_TYPE);
	}

	/**
	 * Create a new instance of javax.net.ssl.TrustManagerFactory for the specified certificate and entry.
	 * @param ca the certificate to trust
	 * @param entry the certificate entry
	 * @return the trust manager factory related to the specified certificate
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public static TrustManagerFactory getTrustManagerFactoryOf(Certificate ca, String entry) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(null, null);
		keyStore.setCertificateEntry(entry, ca);
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(keyStore);
		return tmf;
	}

	/**
	 * Create a new instance of javax.net.ssl.TrustManagerFactory for the specified certificate authority.
	 * @param ca the certificate to trust
	 * @return the trust manager factory related to the specified certificate authority
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public static TrustManagerFactory getTrustManagerFactoryOf(Certificate ca) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
		return getTrustManagerFactoryOf(ca, "ca");
	}

	/**
	 * Create a new instance of javax.net.ssl.SSLSocketFactory will allow safe connections with servers are using
	 * the specified certificate authority.
	 * @param ca the certificate to trust
	 * @return the SSL socket socket factory allows safe connections using <tt>ca</tt>
	 * @throws KeyManagementException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public static SSLSocketFactory getSocketFactoryOf(Certificate ca) throws KeyManagementException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
		TrustManagerFactory tmf = getTrustManagerFactoryOf(ca);
		SSLContext ctx = SSLContext.getInstance(DEF_SSL_PROTO);
		ctx.init(null, tmf.getTrustManagers(), null);
		return ctx.getSocketFactory();
	}

	private static final String DEF_SSL_PROTO = "TLS";
	private static final String DEF_TYPE = "X.509";
	private static final String DEF_CERT =
		"-----BEGIN CERTIFICATE-----\n" +
		"MIIEszCCA5ugAwIBAgIDA2l+MA0GCSqGSIb3DQEBCwUAMEcxCzAJBgNVBAYTAlVT\n" +
		"MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMSAwHgYDVQQDExdSYXBpZFNTTCBTSEEy\n" +
		"NTYgQ0EgLSBHMzAeFw0xNTA0MDEwODM2MjlaFw0xNjA1MDMwMDIxMDlaMIGUMRMw\n" +
		"EQYDVQQLEwpHVDc3MDU4NjAzMTEwLwYDVQQLEyhTZWUgd3d3LnJhcGlkc3NsLmNv\n" +
		"bS9yZXNvdXJjZXMvY3BzIChjKTE1MS8wLQYDVQQLEyZEb21haW4gQ29udHJvbCBW\n" +
		"YWxpZGF0ZWQgLSBSYXBpZFNTTChSKTEZMBcGA1UEAwwQKi5jbG91ZHBsdWdzLmNv\n" +
		"bTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN4whbvQ+q9pqALcWILg\n" +
		"lWwwe3JXc9rdss+O69lp7CPdFZ62YeqJ2RlRJzgI3upyReQ5opFwlrUJ0krAInAa\n" +
		"lxwg9tRBZDDF6D6SSs8rUntCRntn6hj7UFKyjPNGlg0FDI4YTDvdDNl4YxoFlWss\n" +
		"Hhb+YEUZfNe6RLndaCZzfudKFsvGwmQveJnkSdiW8ON0qWXU9sbD5pMVAs03dAo+\n" +
		"rObkqFq3h8TnRlLdd4X4ZIA5VTNXBNY93WfJFdMORikKtjR36y19rXNj7Spza8Sz\n" +
		"PO19I6dB0npo8GOCBQ/83OZaQjieHPFJOwU2Y8NytCTrD9yLt6KL0sVq48DEEML+\n" +
		"OO0CAwEAAaOCAVgwggFUMB8GA1UdIwQYMBaAFMOc8/zTRgg0u85Gf6B8W/PiCMtZ\n" +
		"MFcGCCsGAQUFBwEBBEswSTAfBggrBgEFBQcwAYYTaHR0cDovL2d2LnN5bWNkLmNv\n" +
		"bTAmBggrBgEFBQcwAoYaaHR0cDovL2d2LnN5bWNiLmNvbS9ndi5jcnQwDgYDVR0P\n" +
		"AQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjArBgNVHREE\n" +
		"JDAighAqLmNsb3VkcGx1Z3MuY29tgg5jbG91ZHBsdWdzLmNvbTArBgNVHR8EJDAi\n" +
		"MCCgHqAchhpodHRwOi8vZ3Yuc3ltY2IuY29tL2d2LmNybDAMBgNVHRMBAf8EAjAA\n" +
		"MEEGA1UdIAQ6MDgwNgYGZ4EMAQIBMCwwKgYIKwYBBQUHAgEWHmh0dHBzOi8vd3d3\n" +
		"LnJhcGlkc3NsLmNvbS9sZWdhbDANBgkqhkiG9w0BAQsFAAOCAQEAByeixIdonrY9\n" +
		"z7ZwtYregQBQzD2QhRwe7ojmG3GE6WhgBwzwSN2tmSHVC8ly6LQCMt+7QRNfrTTr\n" +
		"DtgRI/VOS5yWJ12cq/3AZPuUqvnBMMb6yXx0iE3HCKMe/HHKipXzp7qXnHhingeQ\n" +
		"VKL4HUO9niGHIuwX4BDIG9MEiPuIHuB8xloizADk+lCIk2gTVXq4z8JDgokibLgv\n" +
		"qyWmlhoeOiNRVAeERduWTyjFV3/YMzRXxgsZW0sI8wdPLpyGqvVh2Vn1nXu497Sr\n" +
		"BhONF7Nkbs/j3VnAjlMr/W1Dhdj0Fupm+irzZVA5amDK4OVi2sqWTq/3uPWkHAti\n" +
		"cfXBK6Nuwg==\n" +
		"-----END CERTIFICATE-----\n";
}
