// groovyConsole.bat --configscript .\antlr2.groovy .\helloworld.groovy
import static org.codehaus.groovy.control.customizers.builder.CompilerCustomizationBuilder.*
import static org.codehaus.groovy.control.ParserPluginFactory.antlr2

import org.codehaus.groovy.control.CompilerConfiguration

withConfig (configuration) { 
	(configuration as CompilerConfiguration).pluginFactory = antlr2()
}