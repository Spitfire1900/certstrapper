package com.gottfriedstudios.certstrapper

class SupportMethods {

	static ArrayList<Integer> indexesOfCRLFs(File file) {
		char[] charArray = new char[file.size()]
		file.withReader {
			it.read charArray
		}

		def indexesOfCrs = (charArray as List).findIndexValues { it == '\r' as char }
		return indexesOfCrs.findAll { index ->
			index != charArray.size() - 1  && charArray[index + 1 as int] == '\n' as char
		}
	}
}
