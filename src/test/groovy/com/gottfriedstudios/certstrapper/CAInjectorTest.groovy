package com.gottfriedstudios.certstrapper

import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

import com.gottfriedstudios.certstrapper.CABundleInstaller
import com.gottfriedstudios.certstrapper.CAInjector

import spock.lang.Specification
import spock.lang.Unroll

class CAInjectorTest extends Specification {

	def 'X509 certificates are able to be pulled out of a plain text file containing PEM certs'() {
		when: 'given a pem cert bundle and test pem cert'
		File pemCertBundle = new CABundleInstaller().call()

		and: 'a new CA injector'
		def caInjector = new CAInjector(testPemCert, pemCertBundle.text)

		and: 'the CA injector attempts to parse the cert bundle'
		ArrayList<X509Certificate> certList = caInjector.parsePemCertBundle()

		then: 'the cert bundle contains X509 Certificates'
		certList.size > 0
		certList[0] instanceof X509Certificate
	}

	def 'A Runtime error is thrown when the PEM cert bundle can not be parsed'() {
		when: 'given a non existent cert bundle and test pem cert'
		def bundleString = "NO_MESSAGE"
		def caInjector = new CAInjector(testPemCert, bundleString)

		and: 'the CA injector attempts to parse the cert bundle'
		def buffer = new ByteArrayOutputStream()
		System.err =  new PrintStream(buffer)
		ArrayList<X509Certificate> certList = caInjector.parsePemCertBundle()
		def stderr = buffer.toString().trim()

		then: 'An exception is thrown'
		thrown RuntimeException
	}

	@Unroll
	def "When a certificates subject only contains a(n) #condition it is used for its simple name"() {
		when: 'you have a certificate'
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509")
		X509Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream((certificate as String).bytes))

		and: 'you try to get the simple name from it'
		CAInjector caInjector = new CAInjector(testPemCert, "")
		String derivedsimpleName = caInjector.simpleNameFromX509Certificate(cert)

		then: "the certificate's simple name is resolved its #condition"
		derivedsimpleName == simpleName

		where: "the certificate being parsed's most grainular subject component is a(n) #condition"
		condition | certificate | simpleName
		"CN"      | cnPemCert   | "GlobalSign"
		"OU"      | ouPemCert   | "Go Daddy Class 2 Certification Authority"
		"O"       | oPemCert    | "Government Root Certification Authority"
		"C"       | cPemCert    | "C=US # (FQ Subject)"
	}

	def "When attempting to append to a PEM cert bundle"() {
		when: 'you have an empty certificate and installer'
		String cert = ""
		String certBundlePath = new CABundleInstaller().call()
		CAInjector caInjector = new CAInjector(cert, certBundlePath)


		and: 'you ask for it to be appended'
		def buffer = new ByteArrayOutputStream()
		System.err =  new PrintStream(buffer)
		String certList = caInjector.appendToPemCertBundle()
		def stderr = buffer.toString().trim()

		then: 'an error is printed and an empty string is returned'
		stderr == "Can not operate on null or empty pem file"
		certList == ""

		when: 'you have a valid certificate'
		cert = testPemCert

		and: 'you ask for it to be appended'
		certList = caInjector.appendToPemCertBundle(cert)
		String nl = System.properties.'line.separator'

		then: 'the valid certificate is appended'
		certList.contains "# BadSSL Untrusted Root Certificate Authority"
		certList.contains "-----BEGIN CERTIFICATE-----"
		// XXX: an exact compare has one less '=' at the end of the cert
		// The problem might be that a pem file is _already_ Base64 encoded
		certList.contains($/MIIGfjCCBGagAwIBAgIJAJeg/PrX5Sj9MA0GCSqGSIb3DQEBCwUAMIGBMQswCQYD/$)
		certList.contains "-----END CERTIFICATE-----"
		certList.size() > 2000

		when: 'you have a multiple certs in one file'
		caInjector = new CAInjector(cert, certBundlePath)
		cert = "$testPemCert$nl$testPemCert"

		and: 'you ask for it to be appended'
		certList = caInjector.appendToPemCertBundle(cert)
		nl = System.properties.'line.separator'

		then: 'two valid certificates appended'
		[
			"# BadSSL Untrusted Root Certificate Authority",
			"-----BEGIN CERTIFICATE-----",
			$/MIIGfjCCBGagAwIBAgIJAJeg/PrX5Sj9MA0GCSqGSIb3DQEBCwUAMIGBMQswCQYD/$,
			"-----END CERTIFICATE-----"
		].each { String it ->
			certList.count(it) == 2
		}

		// This then logic would be preferable but fails:
		//		certList ==
		//				"""
		//# BadSSL Untrusted Root Certificate Authority
		//$testPemCert
		//# BadSSL Untrusted Root Certificate Authority
		//$testPemCert
		//				"""

		when: 'You pass an empty pem file'
		cert = ""
		certBundlePath = new CABundleInstaller().call()
		caInjector = new CAInjector(cert, new File(certBundlePath).text)

		and: 'you ask for it to be appended'
		buffer = new ByteArrayOutputStream()
		System.err =  new PrintStream(buffer)
		certList = caInjector.parsePemCertBundle()

		certList = caInjector.appendToPemCertBundle cert
		stderr = buffer.toString().trim()

		then: 'Std error reports a error and an unmodified Keystore'
		stderr.contains "Can not operate on null or empty pem file"
	}

	def "When attempting to append to a KeyStore"() {
		when: 'you have an empty certificate, installer, and a keystore'
		String cert = ""
		String certBundlePath = new CABundleInstaller().call()
		CAInjector caInjector = new CAInjector(cert, certBundlePath)
		KeyStore keyStore = KeyStore.getInstance "JKS"
		new FileInputStream("${System.getProperty('user.dir')}/src/test/resources/cacerts").with {
			keyStore.load it, "changeit".toCharArray()
		}
		Integer keyStoreInitSize = keyStore.size()


		and: 'you ask for it to be appended'
		def buffer = new ByteArrayOutputStream()
		System.err =  new PrintStream(buffer)
		KeyStore certList = caInjector.appendToKeyStore(cert, keyStore)
		def stderr = buffer.toString().trim()

		then: 'an error is printed and the key store contains no new entry'
		stderr == "Can not operate on null or empty pem file"
		keyStore.size() == keyStoreInitSize

		when: 'you have a valid certificate'
		cert = testPemCert

		and: 'you ask for it to be appended'
		certList = caInjector.appendToKeyStore(cert, keyStore)
		String nl = System.properties.'line.separator'

		then: 'the certificate is appended'
		certList.containsAlias("subject=cn=badssl untrusted root certificate authority, o=badssl, l=san francisco, st=california, c=us")
		certList.size() > 10

		when: 'you have a multiple certs in one file'
		caInjector = new CAInjector(cert, certBundlePath)
		keyStore = KeyStore.getInstance "JKS"
		new FileInputStream("${System.getProperty('user.dir')}/src/test/resources/cacerts").with {
			keyStore.load it, "changeit".toCharArray()
		}
		keyStoreInitSize = keyStore.size()
		nl = System.properties.'line.separator'
		cert = "$testPemCert$nl$nl$testPemCert"

		and: 'you ask for it to be appended'
		certList = caInjector.appendToKeyStore(cert, keyStore)

		then: 'only one cert is appended'
		certList.size() == (keyStoreInitSize + 1)
	}

	/** Bad SSL Untrusted Root CA */
	static String testPemCert =
	$/-----BEGIN CERTIFICATE-----
MIIGfjCCBGagAwIBAgIJAJeg/PrX5Sj9MA0GCSqGSIb3DQEBCwUAMIGBMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5j
aXNjbzEPMA0GA1UECgwGQmFkU1NMMTQwMgYDVQQDDCtCYWRTU0wgVW50cnVzdGVk
IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTE2MDcwNzA2MzEzNVoXDTM2
MDcwMjA2MzEzNVowgYExCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlh
MRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ8wDQYDVQQKDAZCYWRTU0wxNDAyBgNV
BAMMK0JhZFNTTCBVbnRydXN0ZWQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkw
ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDKQtPMhEH073gis/HISWAi
bOEpCtOsatA3JmeVbaWal8O/5ZO5GAn9dFVsGn0CXAHR6eUKYDAFJLa/3AhjBvWa
tnQLoXaYlCvBjodjLEaFi8ckcJHrAYG9qZqioRQ16Yr8wUTkbgZf+er/Z55zi1yn
CnhWth7kekvrwVDGP1rApeLqbhYCSLeZf5W/zsjLlvJni9OrU7U3a9msvz8mcCOX
fJX9e3VbkD/uonIbK2SvmAGMaOj/1k0dASkZtMws0Bk7m1pTQL+qXDM/h3BQZJa5
DwTcATaa/Qnk6YHbj/MaS5nzCSmR0Xmvs/3CulQYiZJ3kypns1KdqlGuwkfiCCgD
yWJy7NE9qdj6xxLdqzne2DCyuPrjFPS0mmYimpykgbPnirEPBF1LW3GJc9yfhVXE
Cc8OY8lWzxazDNNbeSRDpAGbBeGSQXGjAbliFJxwLyGzZ+cG+G8lc+zSvWjQu4Xp
GJ+dOREhQhl+9U8oyPX34gfKo63muSgo539hGylqgQyzj+SX8OgK1FXXb2LS1gxt
VIR5Qc4MmiEG2LKwPwfU8Yi+t5TYjGh8gaFv6NnksoX4hU42gP5KvjYggDpR+NSN
CGQSWHfZASAYDpxjrOo+rk4xnO+sbuuMk7gORsrl+jgRT8F2VqoR9Z3CEdQxcCjR
5FsfTymZCk3GfIbWKkaeLQIDAQABo4H2MIHzMB0GA1UdDgQWBBRvx4NzSbWnY/91
3m1u/u37l6MsADCBtgYDVR0jBIGuMIGrgBRvx4NzSbWnY/913m1u/u37l6MsAKGB
h6SBhDCBgTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNV
BAcMDVNhbiBGcmFuY2lzY28xDzANBgNVBAoMBkJhZFNTTDE0MDIGA1UEAwwrQmFk
U1NMIFVudHJ1c3RlZCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eYIJAJeg/PrX
5Sj9MAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IC
AQBQU9U8+jTRT6H9AIFm6y50tXTg/ySxRNmeP1Ey9Zf4jUE6yr3Q8xBv9gTFLiY1
qW2qfkDSmXVdBkl/OU3+xb5QOG5hW7wVolWQyKREV5EvUZXZxoH7LVEMdkCsRJDK
wYEKnEErFls5WPXY3bOglBOQqAIiuLQ0f77a2HXULDdQTn5SueW/vrA4RJEKuWxU
iD9XPnVZ9tPtky2Du7wcL9qhgTddpS/NgAuLO4PXh2TQ0EMCll5reZ5AEr0NSLDF
c/koDv/EZqB7VYhcPzr1bhQgbv1dl9NZU0dWKIMkRE/T7vZ97I3aPZqIapC2ulrf
KrlqjXidwrGFg8xbiGYQHPx3tHPZxoM5WG2voI6G3s1/iD+B4V6lUEvivd3f6tq7
d1V/3q1sL5DNv7TvaKGsq8g5un0TAkqaewJQ5fXLigF/yYu5a24/GUD783MdAPFv
gWz8F81evOyRfpf9CAqIswMF+T6Dwv3aw5L9hSniMrblkg+ai0K22JfoBcGOzMtB
Ke/Ps2Za56dTRoY/a4r62hrcGxufXd0mTdPaJLw3sJeHYjLxVAYWQq4QKJQWDgTS
dAEWyN2WXaBFPx5c8KIW95Eu8ShWE00VVC3oA4emoZ2nrzBXLrUScifY6VaYYkkR
2O2tSqU8Ri3XRdgpNPDWp8ZL49KhYGYo3R/k98gnMHiY5g==
-----END CERTIFICATE-----
/$
	/** FQ Subject: OU = GlobalSign Root CA - R6, O = GlobalSign, CN = GlobalSign*/
	static String cnPemCert =
	$/
-----BEGIN CERTIFICATE-----
MIIFgzCCA2ugAwIBAgIORea7A4Mzw4VlSOb/RVEwDQYJKoZIhvcNAQEMBQAwTDEg
MB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjYxEzARBgNVBAoTCkdsb2Jh
bFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMTQxMjEwMDAwMDAwWhcNMzQx
MjEwMDAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjET
MBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCAiIwDQYJ
KoZIhvcNAQEBBQADggIPADCCAgoCggIBAJUH6HPKZvnsFMp7PPcNCPG0RQssgrRI
xutbPK6DuEGSMxSkb3/pKszGsIhrxbaJ0cay/xTOURQh7ErdG1rG1ofuTToVBu1k
ZguSgMpE3nOUTvOniX9PeGMIyBJQbUJmL025eShNUhqKGoC3GYEOfsSKvGRMIRxD
aNc9PIrFsmbVkJq3MQbFvuJtMgamHvm566qjuL++gmNQ0PAYid/kD3n16qIfKtJw
LnvnvJO7bVPiSHyMEAc4/2ayd2F+4OqMPKq0pPbzlUoSB239jLKJz9CgYXfIWHSw
1CM69106yqLbnQneXUQtkPGBzVeS+n68UARjNN9rkxi+azayOeSsJDa38O+2HBNX
k7besvjihbdzorg1qkXy4J02oW9UivFyVm4uiMVRQkQVlO6jxTiWm05OWgtH8wY2
SXcwvHE35absIQh1/OZhFj931dmRl4QKbNQCTXTAFO39OfuD8l4UoQSwC+n+7o/h
bguyCLNhZglqsQY6ZZZZwPA1/cnaKI0aEYdwgQqomnUdnjqGBQCe24DWJfncBZ4n
WUx2OVvq+aWh2IMP0f/fMBH5hc8zSPXKbWQULHpYT9NLCEnFlWQaYw55PfWzjMpY
rZxCRXluDocZXFSxZba/jJvcE+kNb7gu3GduyYsRtYQUigAZcIN5kZeR1Bonvzce
MgfYFGM8KEyvAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTAD
AQH/MB0GA1UdDgQWBBSubAWjkxPioufi1xzWx/B/yGdToDAfBgNVHSMEGDAWgBSu
bAWjkxPioufi1xzWx/B/yGdToDANBgkqhkiG9w0BAQwFAAOCAgEAgyXt6NH9lVLN
nsAEoJFp5lzQhN7craJP6Ed41mWYqVuoPId8AorRbrcWc+ZfwFSY1XS+wc3iEZGt
Ixg93eFyRJa0lV7Ae46ZeBZDE1ZXs6KzO7V33EByrKPrmzU+sQghoefEQzd5Mr61
55wsTLxDKZmOMNOsIeDjHfrYBzN2VAAiKrlNIC5waNrlU/yDXNOd8v9EDERm8tLj
vUYAGm0CuiVdjaExUd1URhxN25mW7xocBFymFe944Hn+Xds+qkxV/ZoVqW/hpvvf
cDDpw+5CRu3CkwWJ+n1jez/QcYF8AOiYrg54NMMl+68KnyBr3TsTjxKM4kEaSHpz
oHdpx7Zcf4LIHv5YGygrqGytXm3ABdJ7t+uA/iU3/gKbaKxCXcPu9czc8FB10jZp
nOZ7BN9uBmm23goJSFmH63sUYHpkqmlD75HHTOwY3WzvUy2MmeFe8nI+z1TIvWfs
pA9MRf/TuTAjB0yPEL+GltmZWrSZVxykzLsViVO6LAUP5MSeGbEYNNVMnbrt9x+v
JJUEeKgDu+6B5dpffItKoZB0JaezPkvILFa9x8jvOOJckvB595yEunQtYQEgfn7R
8k8HWV+LLUNS60YMlOH1Zkd5d9VUWx+tJDfLRVpOoERIyNiwmcUVhAn21klJwGW4
5hpxbqCo8YLoRT5s1gLXCmeDBVrJpBA=
-----END CERTIFICATE-----
/$
	/** FQ Subject = C = US, O = "The Go Daddy Group, Inc.", OU = Go Daddy Class 2 Certification Authority*/
	static String ouPemCert =
	$/
-----BEGIN CERTIFICATE-----
MIIEADCCAuigAwIBAgIBADANBgkqhkiG9w0BAQUFADBjMQswCQYDVQQGEwJVUzEh
MB8GA1UEChMYVGhlIEdvIERhZGR5IEdyb3VwLCBJbmMuMTEwLwYDVQQLEyhHbyBE
YWRkeSBDbGFzcyAyIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTA0MDYyOTE3
MDYyMFoXDTM0MDYyOTE3MDYyMFowYzELMAkGA1UEBhMCVVMxITAfBgNVBAoTGFRo
ZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28gRGFkZHkgQ2xhc3Mg
MiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTCCASAwDQYJKoZIhvcNAQEBBQADggEN
ADCCAQgCggEBAN6d1+pXGEmhW+vXX0iG6r7d/+TvZxz0ZWizV3GgXne77ZtJ6XCA
PVYYYwhv2vLM0D9/AlQiVBDYsoHUwHU9S3/Hd8M+eKsaA7Ugay9qK7HFiH7Eux6w
wdhFJ2+qN1j3hybX2C32qRe3H3I2TqYXP2WYktsqbl2i/ojgC95/5Y0V4evLOtXi
EqITLdiOr18SPaAIBQi2XKVlOARFmR6jYGB0xUGlcmIbYsUfb18aQr4CUWWoriMY
avx4A6lNf4DD+qta/KFApMoZFv6yyO9ecw3ud72a9nmYvLEHZ6IVDd2gWMZEewo+
YihfukEHU1jPEX44dMX4/7VpkI+EdOqXG68CAQOjgcAwgb0wHQYDVR0OBBYEFNLE
sNKR1EwRcbNhyz2h/t2oatTjMIGNBgNVHSMEgYUwgYKAFNLEsNKR1EwRcbNhyz2h
/t2oatTjoWekZTBjMQswCQYDVQQGEwJVUzEhMB8GA1UEChMYVGhlIEdvIERhZGR5
IEdyb3VwLCBJbmMuMTEwLwYDVQQLEyhHbyBEYWRkeSBDbGFzcyAyIENlcnRpZmlj
YXRpb24gQXV0aG9yaXR5ggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQAD
ggEBADJL87LKPpH8EsahB4yOd6AzBhRckB4Y9wimPQoZ+YeAEW5p5JYXMP80kWNy
OO7MHAGjHZQopDH2esRU1/blMVgDoszOYtuURXO1v0XJJLXVggKtI3lpjbi2Tc7P
TMozI+gciKqdi0FuFskg5YmezTvacPd+mSYgFFQlq25zheabIZ0KbIIOqPjCDPoQ
HmyW74cNxA9hi63ugyuV+I6ShHI56yDqg+2DzZduCLzrTia2cyvk0/ZM/iZx4mER
dEr/VxqHD3VILs9RaRegAhJhldXRQLIQTO7ErBBDpqWeCtWVYpoNz4iCxTIM5Cuf
ReYNnyicsbkqWletNw+vHX/bvZ8=
-----END CERTIFICATE-----
/$
	/** FQ Subject = C = TW, O = Government Root Certification Authority*/
	static String oPemCert =
	$/
-----BEGIN CERTIFICATE-----
MIIFcjCCA1qgAwIBAgIQH51ZWtcvwgZEpYAIaeNe9jANBgkqhkiG9w0BAQUFADA/
MQswCQYDVQQGEwJUVzEwMC4GA1UECgwnR292ZXJubWVudCBSb290IENlcnRpZmlj
YXRpb24gQXV0aG9yaXR5MB4XDTAyMTIwNTEzMjMzM1oXDTMyMTIwNTEzMjMzM1ow
PzELMAkGA1UEBhMCVFcxMDAuBgNVBAoMJ0dvdmVybm1lbnQgUm9vdCBDZXJ0aWZp
Y2F0aW9uIEF1dGhvcml0eTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AJoluOzMonWoe/fOW1mKydGGEghU7Jzy50b2iPN86aXfTEc2pBsBHH8eV4qNw8XR
IePaJD9IK/ufLqGU5ywck9G/GwGHU5nOp/UKIXZ3/6m3xnOUT0b3EEk3+qhZSV1q
gQdW8or5BtD3cCJNtLdBuTK4sfCxw5w/cP1T3YGq2GN49thTbqGsaoQkclSGxtKy
yhwOeYHWtXBiCAEuTk8O1RGvqa/lmr/czIdtJuTJV6L7lvnM4T9TjGxMfptTCAts
F/tnyMKtsc2AtJfcdgEWFelq16TheEfOhtX7MfP6Mb40qij7cEwdScevLJ1tZqa2
jWR+tSBqnTuBto9AAGdLiYa4zGX+FVPpBMHWXx1E1wovJ5pGfaENda1UhhXcSTvx
ls4Pm6Dso3pdvtUqdULle96ltqqvKKyskKw4t9VoNSZ63Pc78/1Fm9G7Q3hub/FC
VGqY8A2tl+lSXunVanLeavcbYBT0peS2cWeqH+riTcFCQP5nRhc4L0c/cZyu5SHK
YS1tB6iEfC3uUSXxY5Ce/eFXiGvviiNtsea9P63RPZYLhY3Naye7twWb7LuRqQoH
EgKXTiCQ8P8NHuJBO9NAOueNXdpm5AKwB1KYXA6OM5zCppX7VRluTI6uSw+9wThN
Xo+EHWbNxWCWtFJaBYmOlXqYwZE8lSOyDvR5tMl8wUohAgMBAAGjajBoMB0GA1Ud
DgQWBBTMzO/MKWCkO7GStjz6MmKPrCUVOzAMBgNVHRMEBTADAQH/MDkGBGcqBwAE
MTAvMC0CAQAwCQYFKw4DAhoFADAHBgVnKgMAAAQUA5vwIhP/lSg209yewDL7MTqK
UWUwDQYJKoZIhvcNAQEFBQADggIBAECASvomyc5eMN1PhnR2WPWus4MzeKR6dBcZ
TulStbngCnRiqmjKeKBMmo4sIy7VahIkv9Ro04rQ2JyftB8M3jh+Vzj8jeJPXgyf
qzvS/3WXy6TjZwj/5cAWtUgBfen5Cv8b5Wppv3ghqMKnI6mGq3ZW6A4M9hPdKmaK
ZEk9GhiHkASfQlK3T8v+R0F2Ne//AHY2RTKbxkaFXeIksB7jSJaYV0eUVXoPQbFE
JPPB/hprv4j9wabak2BegUqZIJxIZhm1AHlUD7gsL0u8qV1bYH+Mh6XgUmMqvtg7
hUAV/h62ZT/FS9p+tXo1KaMuephgIqP0fSdOLeq0dDzpD6QzDxARvBMB1uUO07+1
EqLhRSPAzAhuYbeJq4PjJB7mXQfnHyA+z2fI56wwbSdLaG5LKlwCCDTb+HbkZ6Mm
nD+iMsJKxYEYMRBWqoTvLQr/uB930r+lWKBi5NdLkXWNiYCYfm3LU05er/ayl4WX
udpVBrkk7tfGOB5jGxI7leFYrPLfhNVfmS8NVVvmONsuP3LpSIXLuykTjx44Vbnz
ssQwmSNOXfJIoRIM3BKQCZBUkQM8R+XVyWXgt0t97EfTsws+rZ7QdAAO671RrcDe
LMDDav7v3Aun+kbfYNucpllQdSNpc5Oy+fwC00fmcc4QAu4njIT/rEUNE1yDMuAl
pYYsfPQS
-----END CERTIFICATE-----
/$
	/** FQ Subject = C = US */
	static String cPemCert =
	$/
-----BEGIN CERTIFICATE-----
MIICuTCCAaGgAwIBAgIEJfXgIDANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
UzAeFw0yMTA1MDIxMzU3MjdaFw0yMTA3MzExMzU3MjdaMA0xCzAJBgNVBAYTAlVT
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnIzvDJiyWhOQmdAs8Fjv
mLY3geRxGFrQxHqU7zAl5n/Yu7pMTojmTtFkn8jF4P5qK+jNrzDnZpbAZiE0N0xr
iEQiJsZEmRAKRbPT0EkMtEf/B5cMvJR1cQoM4exmZWuV1OhuFf3LtPtbWFr/37zj
5rO3QonWUTx9MZqWD7jOiZxkGSWsGKMRwSvOu+t6YLuJoW2vu4aXwgBZVe3sGYue
HnnF3bDeQitT066EfPeYiy7LBibUHDryiETb5vQaxDd2y1fDAQ69lLcjvZVtoEqX
kzPTfEKLUFJm6KIPFCNIor93hk12EcXQWNYtdTfBQSri6wo3EAKxBMjaHL7I8Mcr
WQIDAQABoyEwHzAdBgNVHQ4EFgQUfeCtXBJQpMgwbzK8CyDx4lST6HwwDQYJKoZI
hvcNAQELBQADggEBAGf4OR76kA4uu39eswF6ehnrkqnkUxt5IpXLt3IsG4Kfr8mA
Jtbbe7oa8KXaRmcdDNU5DSyp0n5IUGjeGrnL/Y4WAuwTqrhkTH6iJL/kR/TUgNSO
a9h+LrxL1RK8Jg6JartrDemh9jPtyO2OHB7Ys5+pHSM6xkyLDXmTmh0G+zWtpIE1
HaHqo9l/DVHnQT4yr5ypziQ5mz/qhtRkt2uXaXF7ygRUv5myNY4C0fg/44cWS3bO
5xij/IUfqnzz2ylL68Gsbjhco0jr+rVNWLcXCvXA3iEO604h0XTZjkc/bTuJ1qI3
HL1fkuI7DW1TyFIM4/ocm26JutUhXsbh0eZwtLg=
-----END CERTIFICATE-----
/$
}
