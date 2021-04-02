package com.gottfriedstudios.certstrapper

class CABundleInstaller {

	String[] gitPaths = [
		"${System.getenv 'LOCALAPPDATA'}/Programs/Git",
		"C:/Program Files/Git",
		"C:/Program Files (x86)/Git"
	]
	String gitOpenSslCaBundleFilename = 'ca-bundle.crt'

	private defaultCertsFileNameWinGit = "/usr/ssl/certs/${gitOpenSslCaBundleFilename}"


	def getGitPath() {
		gitPaths.find {
			new File(it).isDirectory()
		}
	}

	File getGitCertsFile() {
		if (!gitPath) {
			throw new RuntimeException("A git install was not found in any of the following locations: ${gitPaths}")
		}
		return new File(gitPath + defaultCertsFileNameWinGit)
	}

	def call() {
		CertStrapper.DATA_HOME.toFile().mkdirs()
		if (!gitCertsFile.isFile()) {
			throw new RuntimeException("The path '${gitCertsFile}' does not exist or is not a file")
		}
		def certStrapperPemBundle = new File("${CertStrapper.DATA_HOME}/${gitOpenSslCaBundleFilename}")
		certStrapperPemBundle.text = gitCertsFile.text
		return certStrapperPemBundle
	}

	// https://blog.mrhaki.com/2017/02/groovy-goodness-using-call-operator.html
	def call(final Closure runCode) {
		runCode this
	}
}
