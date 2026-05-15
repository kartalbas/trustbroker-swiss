/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
 *
 * This program is free software.
 * You can redistribute it and/or modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the GNU Affero General Public License for more details.
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 */

package swiss.trustbroker.homerealmdiscovery.util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import javax.xml.XMLConstants;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import jakarta.xml.bind.util.ValidationEventCollector;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.ConfigurableEnvironment;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.util.CollectionUtil;
import swiss.trustbroker.common.util.DirectoryUtil;
import swiss.trustbroker.exception.GlobalExceptionHandler;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderDefinitions;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderMappings;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderSetup;
import swiss.trustbroker.federation.xmlconfig.PathReference;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;
import swiss.trustbroker.federation.xmlconfig.SsoGroupSetup;

/**
 * Handles XML config parsing via JAXB. This class is used in static context, hence the static map.
 */
@Slf4j
public class XmlConfigUtil {

	private record XmlContext(JAXBContext jaxbContext, Schema schema) {}

	record LoadResult <T> (List<T> result, Map<String, TechnicalException> skipped) {}

	private static final String CONFIG_FILE_EXTENSION = ".xml";

	// classes handled by this class
	private static final List<Class<?>> SCHEMA_CLASSES = List.of(
			ClaimsProviderDefinitions.class,
			ClaimsProviderMappings.class,
			ClaimsProviderSetup.class,
			RelyingParty.class,
			RelyingPartySetup.class,
			SsoGroupSetup.class
	);

	// https://javaee.github.io/jaxb-v2/doc/user-guide/ch06.html
	// The JAXB Specification currently does not address the thread safety of the runtime classes.
	// In the case of the Oracle JAXB RI, the JAXBContext class is thread safe, but the Marshaller,
	// Unmarshaller, and Validator classes are not thread safe.
	// https://docs.oracle.com/javase/8/docs/api/javax/xml/validation/Schema.html
	//  A Schema object is thread safe and applications are encouraged to share it across many parsers in many threads.
	private static final Map<Class<?>, XmlContext> XML_CONTEXTS;

	static {
		log.info("Initializing XSD/JAXB contexts for {}", SCHEMA_CLASSES);
		XML_CONTEXTS = initXmlContexts();
	}

	private XmlConfigUtil() {
	}

	// load multiple files
	public static <T> LoadResult<T> loadConfigFromDirectory(File mappingFile, Class<T> entryType,
															ConfigurableEnvironment environment) {
		var definitionDirectory = mappingFile.getParentFile();
		if (definitionDirectory == null || !definitionDirectory.isDirectory()) {
			log.error("Cannot iterate over directory {}", definitionDirectory);
			return new LoadResult<>(Collections.emptyList(), Collections.emptyMap());
		}
		var filePrefix = filePrefix(mappingFile);
		Map<String, TechnicalException> skipped = new ConcurrentHashMap<>();
		var definitionPath = definitionDirectory.toPath();
		try (var stream = Files.walk(definitionPath, FileVisitOption.FOLLOW_LINKS)) {
			var entries = stream
					.filter(Files::isRegularFile)
					.filter(file -> isMatchingFile(file, filePrefix))
					.map(file -> loadConfigFromFile(file, definitionPath, entryType, skipped, environment))
					.filter(Objects::nonNull) // ignore skipped entries
					.toList();
			return new LoadResult<>(entries, skipped);
		}
		catch (IOException ex) {
			throw new TechnicalException(String.format("Could not traverse path=%s message=%s",
					definitionDirectory.getAbsolutePath(), ex.getMessage()), ex);
		}
	}

	// SetupXY.xml => SetupXY
	private static String filePrefix(File mappingFile) {
		return mappingFile.getName().replace(CONFIG_FILE_EXTENSION, "");
	}

	private static boolean isMatchingFile(Path configPath, String filePrefix) {
		var fileName = configPath.getFileName().toString();
		return fileName.startsWith(filePrefix) && fileName.endsWith(CONFIG_FILE_EXTENSION);
	}

	private static <T> T loadConfigFromFile(Path configPath, Path definitionPath, Class<T> entryType,
			Map<String, TechnicalException> skipped, ConfigurableEnvironment environment) {
		var configFile = configPath.toFile();
		try {
			var result = loadConfigFromFile(configFile, entryType, environment);
			if (result instanceof PathReference holder) {
				var subPath = DirectoryUtil.relativePath(configPath.getParent(), definitionPath, false);
				log.debug("Config file={} of type={} is in subPath={}", configPath, result.getClass().getSimpleName(), subPath);
				holder.setSubPath(subPath.toString());
			}
			return result;
		}
		catch (TechnicalException ex) {
			if (log.isDebugEnabled()) {
				log.error("Could not load config: {}", ex.getInternalMessage(), ex);
			}
			else {
				log.error("Could not load config: {}", ex.getInternalMessage()); // exception stack too verbose
			}
			skipped.put(configFile.getAbsolutePath(), ex);
			return null;
		}
	}

	private static Map<Class<?>, XmlContext> initXmlContexts() {
		try {
			SchemaFactory sf = createSchemaFactory();
			Map<Class<?>, XmlContext> xmlContexts = new HashMap<>();
			// having the list of known classes static avoids need for synchronization on the map
			// not too nice but the list of classes is very static, and missing entries are discovered by tests / at start-up
			for (var configType : SCHEMA_CLASSES) {
				var jaxbContext = JAXBContext.newInstance(configType);
				var schema = sf.newSchema(new Source[] { new StreamSource(definitionFileFromClassloader(configType)) });
				xmlContexts.put(configType, new XmlContext(jaxbContext, schema));
			}
			return Collections.unmodifiableMap(xmlContexts);
		}
		catch (SAXException ex) {
			log.error("Could not initialize Schemas");
			throw new IllegalArgumentException(String.format("Could not initialize Schema: %s", ex.getMessage()), ex);
		}
		catch (JAXBException ex) {
			log.error("Could not initialize JaxbContexts");
			throw new IllegalArgumentException(String.format("Could not initialize JaxbContexts: %s", ex.getMessage()), ex);
		}
	}

	private static SchemaFactory createSchemaFactory() throws SAXNotRecognizedException, SAXNotSupportedException {
		SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		// prohibit the use of all protocols by external entities:
		sf.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		sf.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
		return sf;
	}

	private static InputStream definitionFileFromClassloader(Class<?> cls) {
		var xsd = cls.getSimpleName() + ".xsd";
		var cl = XmlConfigUtil.class.getClassLoader();
		var stream = cl.getResourceAsStream(xsd);
		if (stream == null) {
			throw new IllegalArgumentException(String.format("Could not find '%s' via classloader %s", xsd, cl));
		}
		return stream;
	}

	public static Unmarshaller createUnmarshaller(Class<?> configType) {
		try {
			var xmlContext = XML_CONTEXTS.get(configType);
			if (xmlContext == null) {
				throw new TechnicalException(String.format("No XmlContext for configType='%s'", configType.getSimpleName()));
			}
			var unmarshaller = xmlContext.jaxbContext.createUnmarshaller();
			// without the schema, not all issues are detected (e.g. missing mandatory fields, wrong attributes)
			unmarshaller.setSchema(xmlContext.schema);
			return unmarshaller;
		}
		catch (JAXBException ex) {
			throw new TechnicalException(String.format("Could not create Unmarshaller for configType='%s': %s",
					configType.getSimpleName(), ex.getMessage()), ex);
		}
	}

	// uncool workaround for LDAP queries containing placeholders representing attribute references
	private static boolean skipXmlElement(String key, String content, int end) {
		var xmlEndTag = content.indexOf("</", end);
		if (xmlEndTag >= 0 && content.substring(xmlEndTag).startsWith("</AppFilter>", xmlEndTag)) {
			log.warn("Skipping property={} substitution in <AppFilter> element", key);
			return true;
		}
		return false;
	}

	// read file with ${} substitutions from env (ENV variables, JVM and application properties)
	static InputStream handlePlaceholders(InputStream configStream, ConfigurableEnvironment environment) throws IOException {
		var content = new String(configStream.readAllBytes());
		var start = content.indexOf("${");
		while (start >= 0) {
			var end = content.indexOf("}", start + 2);
			if (end < 0) {
				break;
			}
			var key = content.substring(start + 2, end);
			var value = environment != null ? environment.getProperty(key) : null;
			if (value != null && !skipXmlElement(key, content, end)) {
				content = content.substring(0, start) + value + content.substring(end + 1);
			}
			start = content.indexOf("${", start + 2);
		}
		return new ByteArrayInputStream(content.getBytes());
	}

	@SuppressWarnings("unchecked")
	public static <T> T getConfigData(File configFile, Class<T> configType, ConfigurableEnvironment environment) {
		try (var configFromFile = new FileInputStream(configFile)) {
			var configBytes =  configFromFile.readAllBytes();
			var configStream = handlePlaceholders(new ByteArrayInputStream(configBytes), environment);
			var jaxbUnmarshaller = createUnmarshaller(configType);
			// collect validation events of all severities (fails only on FATAL_ERROR):
			var vec = new ValidationEventCollector();
			jaxbUnmarshaller.setEventHandler(vec);
			T result = (T) jaxbUnmarshaller.unmarshal(configStream);
			if (vec.hasEvents()) {
				throw new TechnicalException(String.format("Invalid configFile='%s' loading configType='%s': %s",
						configFile.getAbsolutePath(), configType.getSimpleName(), CollectionUtil.toLogString(vec.getEvents())));
			}
			return result;
		}
		catch (JAXBException | IOException ex) {
			// using toString here instead of getMessage as SAXParseException message is missing line/column
			var causingMessage = GlobalExceptionHandler.getMessageOfExceptionOrCause(ex, true);
			throw new TechnicalException(String.format("Invalid configFile='%s' loading configType='%s': %s",
					configFile.getAbsolutePath(), configType.getSimpleName(), causingMessage), ex);
		}
	}

	// load from a single file containing N definitions including ${property} substitution
	public static <T> T loadConfigFromFile(File configFile, Class<T> entryType, ConfigurableEnvironment environment) {
		var configData = getConfigData(configFile, entryType, environment);
		log.debug("Loaded definition type {} from: {}", entryType.getSimpleName(), configFile.getAbsolutePath());
		return configData;
	}

}
