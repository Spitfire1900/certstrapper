package com.gottfriedstudios.certstrapper

import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSession

import org.apache.http.client.HttpClient
import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.client.methods.HttpGet
import org.apache.http.conn.ssl.SSLConnectionSocketFactory
import org.apache.http.conn.ssl.TrustAllStrategy
import org.apache.http.impl.client.HttpClientBuilder
import org.apache.http.impl.client.HttpClients
import org.apache.http.ssl.SSLContextBuilder
import org.apache.http.util.EntityUtils

import groovy.transform.NullCheck

@NullCheck
class CAInjector {
	String pemFile
	String pemCertBundle


	CAInjector(String pemFile, String pemCertBundle) {
		this.pemFile = pemFile
		this.pemCertBundle = pemCertBundle
	}

	ArrayList<X509Certificate> parsePemCertBundle(String pemCertBundle=this.pemCertBundle) {
		try {
			def certs = CertificateFactory.getInstance("X.509").generateCertificates new ByteArrayInputStream(pemCertBundle.bytes)
			return certs
		} catch (CertificateException exception) {
			System.err.println "The cert bundle $pemCertBundle could not be parsed"
			exception.printStackTrace()
		}
		def nl = System.properties.'line.separator'
		throw new RuntimeException("The cert bundle$nl$pemCertBundle" + " appears to be empty")
	}

	String simpleNameFromX509Certificate(X509Certificate x509Certificate) {
		return \
				   x509Certificate.subjectDN.name.find(/(?<=CN=).*?(?=[,|$])/) // CN
				?: x509Certificate.subjectDN.name.find(/(?<=OU=).*?(?=[,|$])/) // OU
				?: x509Certificate.subjectDN.name.find(/(?<=O=).*?(?=[,|$])/)  // O
				?: x509Certificate.subjectDN.name + ' # (FQ Subject)'          // FQ Subject
	}


	String appendToPemCertBundle(String pemFile=this.pemFile, String pemCertBundle=this.pemCertBundle) {
		def testLength = pemFile.length()
		if (!pemFile) {
			System.err.println "Can not operate on null or empty pem file"
			return ""
		}
		StringBuffer returnString = new StringBuffer("")
		parsePemCertBundle(pemFile).each { X509Certificate cert ->
			String pemCert = new StringBuilder().with {
				Closure appendln = { String string -> append(string + ('\n' as char)) }
				appendln ""
				def name = simpleNameFromX509Certificate cert
				appendln "# $name"
				appendln "-----BEGIN CERTIFICATE-----"
				def certCharArray = Base64.encoder.encodeToString(cert.encoded).toCharArray()
				def columnWidth = 64
				def stepper = (0..<certCharArray.size()).step(columnWidth)
				stepper.each {
					def upperBound = (it + columnWidth > certCharArray.size() - 1) ? certCharArray.size() - 1 : it + columnWidth
					appendln(certCharArray[it..<upperBound].join(''))
				}
				appendln "-----END CERTIFICATE-----"
			}
			returnString << pemCert
		}
		return returnString.toString()
	}

	KeyStore appendToKeyStore(String pemFile=this.pemFile, KeyStore keyStore) {
		if (!pemFile) {
			System.err.println "Can not operate on null or empty pem file"
			return null
		}
		if (!keyStore.initialized) {
			System.err.println "Unable to operate on non-initialized keystore"
			return null
		}

		ArrayList<X509Certificate> pemCertBundle = parsePemCertBundle(pemFile)
		pemCertBundle.each { X509Certificate cert ->
			keyStore.setCertificateEntry "subject=$cert.subjectDN.name", cert
		}

		return keyStore
	}

	def inject() {
		SSLContext sslContext = (SSLContextBuilder.create().with {
			loadKeyMaterial null, null
			loadTrustMaterial KeyStore.getInstance(KeyStore.defaultType), new TrustAllStrategy()
			setProtocol "TLSv1.2"
		} as SSLContextBuilder).build()
		SSLConnectionSocketFactory sslConnectionSocketFactory =
				new SSLConnectionSocketFactory(sslContext,
				new HostCustomVerifer())

		HttpClient httpClient = (HttpClients.custom().with {
			setSSLSocketFactory sslConnectionSocketFactory
			setMaxConnTotal 200
			setMaxConnPerRoute 200
		} as HttpClientBuilder).build()

		(httpClient.execute(new HttpGet('https://untrusted-root.badssl.com/index.html')) as CloseableHttpResponse).withCloseable {
			new File(CertStrapper.DATA_HOME + '/index.html').text = EntityUtils.toString(it.entity, StandardCharsets.UTF_8)
		}
	}
}

class HostCustomVerifer implements HostnameVerifier {
	@Override
	boolean verify(String hostname, SSLSession session) {
		System.err.println "Verifying: " + hostname
		System.err.println session.getPeerCertificates()
		return true
	}
}
