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
		"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\n" +
		"swIxxmLvKtDU\n" +
		"-----END CERTIFICATE-----\n";
}
