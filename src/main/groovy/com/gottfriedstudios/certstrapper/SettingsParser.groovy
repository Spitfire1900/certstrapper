package com.gottfriedstudios.certstrapper

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.ObjectWriter
import com.fasterxml.jackson.dataformat.toml.TomlFactory
import com.fasterxml.jackson.dataformat.toml.TomlMapper

public class SettingsParser {

	void parseSettings() {
		String toml = '''
	brand = "ford"
	doors = 5
	'''
		// File toml = new File(settingsInput)
		// yaml.withReader() { reader ->
		ObjectMapper tomlReader = new TomlMapper(new TomlFactory())
		LinkedHashMap  tomlObj = tomlReader.readValue(toml, LinkedHashMap)
		ObjectWriter tomlWriter = new ObjectMapper().writerWithDefaultPrettyPrinter()
		String toml2json = tomlWriter.writeValueAsString(tomlObj)
		String inputJson = toml2json
		println inputJson
		// }
	}
}
