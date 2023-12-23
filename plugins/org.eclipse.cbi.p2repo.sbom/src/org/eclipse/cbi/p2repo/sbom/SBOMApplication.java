/**
 * Copyright (c) 2023 Eclipse contributors and others.
 *
 * This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.eclipse.cbi.p2repo.sbom;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.cyclonedx.BomGeneratorFactory;
import org.cyclonedx.CycloneDxSchema;
import org.cyclonedx.generators.json.BomJsonGenerator;
import org.cyclonedx.generators.xml.BomXmlGenerator;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Component.Scope;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.License;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.Property;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.NullProgressMonitor;
import org.eclipse.core.runtime.Status;
import org.eclipse.equinox.app.IApplication;
import org.eclipse.equinox.app.IApplicationContext;
import org.eclipse.equinox.internal.p2.artifact.repository.simple.SimpleArtifactRepository;
import org.eclipse.equinox.p2.core.ProvisionException;
import org.eclipse.equinox.p2.internal.repository.tools.AbstractApplication;
import org.eclipse.equinox.p2.internal.repository.tools.RepositoryDescriptor;
import org.eclipse.equinox.p2.metadata.IArtifactKey;
import org.eclipse.equinox.p2.metadata.IInstallableUnit;
import org.eclipse.equinox.p2.metadata.IRequirement;
import org.eclipse.equinox.p2.metadata.expression.IMatchExpression;
import org.eclipse.equinox.p2.query.IQuery;
import org.eclipse.equinox.p2.query.QueryUtil;
import org.eclipse.equinox.p2.repository.artifact.ArtifactKeyQuery;
import org.eclipse.equinox.p2.repository.artifact.IArtifactDescriptor;
import org.eclipse.equinox.p2.repository.artifact.IArtifactRepositoryManager;
import org.eclipse.equinox.p2.repository.metadata.IMetadataRepository;
import org.eclipse.equinox.p2.repository.metadata.IMetadataRepositoryManager;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.ctc.wstx.stax.WstxOutputFactory;

@SuppressWarnings("restriction")
public class SBOMApplication implements IApplication {

	private static final Comparator<IArtifactKey> ARTIFACT_COMPARATOR = new Comparator<IArtifactKey>() {
		@Override
		public int compare(IArtifactKey o1, IArtifactKey o2) {
			int result = o1.getClassifier().compareTo(o2.getClassifier());
			if (result == 0) {
				result = o1.getId().compareTo(o2.getId());
				if (result == 0) {
					result = o1.getVersion().compareTo(o2.getVersion());
				}
			}
			return result;
		}
	};

	private static final Pattern MAVEN_POM_PATTERN = Pattern.compile("META-INF/maven/[^/]+/[^/]+/pom.xml");

	private static final XPathFactory XPATH_FACTORY = XPathFactory.newInstance();

	private static final List<String> ALGORITHMS = List.of("MD5", "SHA-1", "SHA-256", "SHA-512", "SHA-384", "SHA3-384",
			"SHA3-256", "SHA3-512");

	private static final Collector<CharSequence, ?, String> INDENTED_PROPERTY_VALUE_COLLECTOR = Collectors
			.joining("\n      ", "\n      ", "\n    ");

	@Override
	public Object start(IApplicationContext context) throws Exception {
		new SBOMGenerator(context).run(new NullProgressMonitor());

		return null;
	}

	public void stop() {
	}

	private static String getText(Element element, String name) {
		var nodeList = element.getElementsByTagName(name);
		if (nodeList.getLength() > 0) {
			return nodeList.item(0).getTextContent();
		}
		return null;
	}

	private static List<Element> evaluate(Node node, String expression) {
		XPath xPath = XPATH_FACTORY.newXPath();
		try {
			NamespaceContext namespaceContext = new NamespaceContext() {
				@Override
				public Iterator<String> getPrefixes(String namespaceURI) {
					return null;
				}

				@Override
				public String getPrefix(String namespaceURI) {
					return null;
				}

				@Override
				public String getNamespaceURI(String prefix) {
					return "http://maven.apache.org/POM/4.0.0";
				}
			};

			xPath.setNamespaceContext(namespaceContext);

			var nodeList = (NodeList) xPath.compile(expression).evaluate(node, XPathConstants.NODESET);
			var result = new ArrayList<Element>();
			for (int i = 0, length = nodeList.getLength(); i < length; ++i) {
				result.add((Element) nodeList.item(i));
			}
			return result;
		} catch (XPathExpressionException e) {
			throw new IllegalArgumentException(expression);
		}
	}

	private static String computeHash(String algorithm, byte[] bytes) {
		try {
			MessageDigest digest = MessageDigest.getInstance(algorithm);
			byte[] result = digest.digest(bytes);
			return HexFormat.of().formatHex(result);
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	private static Property createProperty(String name, Stream<? extends CharSequence> values) {
		Property property = new Property();
		property.setName(name);
		property.setValue(values.collect(INDENTED_PROPERTY_VALUE_COLLECTOR));
		return property;
	}

	public static BomXmlGenerator createBomXMLGenerator(CycloneDxSchema.Version version, Bom bom) {
		Thread thread = Thread.currentThread();
		ClassLoader contextClassLoader = thread.getContextClassLoader();
		String propertyName = XMLOutputFactory.class.getName();
		String property = System.getProperty(propertyName);
		try {
			System.setProperty(propertyName, WstxOutputFactory.class.getName());
			thread.setContextClassLoader(SBOMApplication.class.getClassLoader());
			return BomGeneratorFactory.createXml(version, bom);
		} finally {
			if (property == null) {
				System.clearProperty(propertyName);
			} else {
				System.setProperty(propertyName, property);
			}
			thread.setContextClassLoader(contextClassLoader);
		}
	}

	private static boolean getArgument(String name, List<String> args) {
		return args.remove(name);
	}

	private static String getArgument(String name, List<String> args, String defaultValue) {
		int index = args.indexOf(name);
		if (index == -1) {
			return defaultValue;
		} else {
			args.remove(index);
			if (index >= args.size()) {
				throw new IllegalArgumentException("An argument value is expected after " + name);
			}
			return args.remove(index);
		}
	}

	@SuppressWarnings("unused")
	private static List<String> getArguments(String name, List<String> args, List<String> defaultValue) {
		int index = args.indexOf(name);
		if (index == -1) {
			return defaultValue;
		} else {
			args.remove(index);
			if (index >= args.size()) {
				throw new IllegalArgumentException("An argument value is expected after " + name);
			}

			List<String> result = new ArrayList<>();
			while (index < args.size() && !args.get(index).startsWith("-")) {
				result.add(args.remove(index));
			}
			return result;
		}
	}

	record MavenDescriptor(String groupId, String artifactId, String version) {
		public static MavenDescriptor create(IInstallableUnit iu) {
			var mavenRepository = iu.getProperty("maven-repository");
			var wrapped = false;

			var mavenGroupId = iu.getProperty("maven-groupId");
			if (mavenGroupId == null) {
				mavenGroupId = iu.getProperty("maven-wrapped-groupId");
				wrapped = true;
			}

			var mavenArtifactId = iu.getProperty("maven-artifactId");
			if (mavenArtifactId == null) {
				mavenArtifactId = iu.getProperty("maven-wrapped-artifactId");
				wrapped = true;
			}

			var mavenVersion = iu.getProperty("maven-version");
			if (mavenVersion == null) {
				mavenVersion = iu.getProperty("maven-wrapped-version");
				wrapped = true;
			}

			if ((wrapped || "central".equals(mavenRepository) || "central-id".equals(mavenRepository)
					|| "eclipse.maven.central.mirror".equals(mavenRepository)) && //
					mavenGroupId != null && mavenArtifactId != null && mavenVersion != null) {
				return new MavenDescriptor(mavenGroupId, mavenArtifactId, mavenVersion);
			}

			return null;
		}

		public String toURL() {
			return "https://repo1.maven.org/maven2/" + groupId.replace('.', '/') + "/" + artifactId + "/" + version
					+ "/" + artifactId + "-" + version + ".pom";
		}
	}

	public static class ContentHandler {

		private Path cache;

		private HttpClient httpClient;

		public ContentHandler(String cache) {
			httpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();

			try {
				if (cache != null) {
					this.cache = Path.of(cache);
				} else {
					this.cache = Files.createTempDirectory("org.eclipse.cbi.p2repo.sbom.cache");
				}
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		protected String basicGetContent(URI uri) throws IOException, InterruptedException {
			var requestBuilder = HttpRequest.newBuilder(uri).GET();
			var request = requestBuilder.build();
			var response = httpClient.send(request, BodyHandlers.ofString());
			var statusCode = response.statusCode();
			if (statusCode != 200) {
				throw new IOException("status code " + statusCode + " -> " + uri);
			}
			return response.body();
		}

		protected Path getCachePath(URI uri) {
			var decodedURI = URLDecoder.decode(uri.toString(), StandardCharsets.UTF_8);
			var uriSegments = decodedURI.split("[:/?#&;]+");
			var result = cache.resolve(String.join("/", uriSegments));
			return result;
		}

		public String getContent(URI uri) throws IOException {
			if ("file".equals(uri.getScheme())) {
				return Files.readString(Path.of(uri));
			}

			var path = getCachePath(uri);
			if (Files.isRegularFile(path)) {
				var lastModifiedTime = Files.getLastModifiedTime(path);
				var now = System.currentTimeMillis();
				var age = now - lastModifiedTime.toMillis();
				var ageInHours = age / 1000 / 60 / 60;
				if (ageInHours < 8) {
					return Files.readString(path);
				}
			}

			try {
				var content = basicGetContent(uri);
				Files.createDirectories(path.getParent());
				Files.writeString(path, content);
				return content;
			} catch (InterruptedException e) {
				throw new IOException(e);
			}
		}

		public Document getXMLContent(URI uri) throws IOException {
			var content = getContent(uri);
			var factory = DocumentBuilderFactory.newInstance();
			factory.setNamespaceAware(true);
			factory.setValidating(false);
			try {
				var builder = factory.newDocumentBuilder();
				return builder.parse(new InputSource(new StringReader(content)));
			} catch (ParserConfigurationException | SAXException e) {
				throw new IOException(uri + " : " + e.getMessage(), e);
			}
		}
	}

	private static class SBOMGenerator extends AbstractApplication {

		private static final Pattern REJECTED_LICENSE_URL_PATTERN = Pattern.compile(".*(legal|license|/MPL).*[^/]",
				Pattern.CASE_INSENSITIVE);

		private static final Pattern POTENTIAL_LICENSE_REFERENCE_PATTERN = Pattern
				.compile("href=['\"]https?://(.*?)['\"]");

		private static final Pattern EPL_20_NAME_PATTERN = Pattern.compile("epl-?(2.0|v20).*.html?");

		private final IApplicationContext context;

		private final DocumentBuilderFactory factory;

		private final Set<String> rejectedURLs = new TreeSet<String>();

		private final Set<String> allLicenses = new TreeSet<String>();

		private final ContentHandler contentHandler;

		private SBOMGenerator(IApplicationContext context) {
			this.context = context;

			factory = DocumentBuilderFactory.newInstance();
			factory.setNamespaceAware(true);
			factory.setValidating(false);
			contentHandler = new ContentHandler(null);
			try {
				factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
				factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
				factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
			} catch (ParserConfigurationException e) {
				throw new RuntimeException(e.getMessage(), e);
			}
		}

		@Override
		public IStatus run(IProgressMonitor monitor) throws ProvisionException {
			List<String> args = new ArrayList<>(
					Arrays.asList((String[]) context.getArguments().get("application.args")));

			boolean verbose = getArgument("-verbose", args);
			boolean relativize = getArgument("-relativize", args);

			String inputArgument = getArgument("-input", args, null);
			if (inputArgument == null) {
				System.err.println("An '-input' argument is required");
				return Status.CANCEL_STATUS;
			}

			IArtifactRepositoryManager artifactRepositoryManager = getArtifactRepositoryManager();
			IMetadataRepositoryManager metadataRepositoryManager = getMetadataRepositoryManager();

			URI uri = URI.create(inputArgument);

			RepositoryDescriptor repositoryDescriptor = new RepositoryDescriptor();
			repositoryDescriptor.setLocation(uri);
			addSource(repositoryDescriptor);

			IMetadataRepository metadataRepository = metadataRepositoryManager.loadRepository(uri, monitor);
			SimpleArtifactRepository artifactRepository = (SimpleArtifactRepository) artifactRepositoryManager
					.loadRepository(uri, monitor);

			Set<IInstallableUnit> allIUs = metadataRepository.query(QueryUtil.ALL_UNITS, monitor).toSet();

			Map<IArtifactKey, Set<IInstallableUnit>> artifactIUs = new TreeMap<IArtifactKey, Set<IInstallableUnit>>(
					ARTIFACT_COMPARATOR);

			Map<IInstallableUnit, IInstallableUnit> featureJarsToFeatures = new HashMap<IInstallableUnit, IInstallableUnit>();
			Map<IInstallableUnit, IInstallableUnit> featuresToFeatureJars = new HashMap<IInstallableUnit, IInstallableUnit>();

			Set<IInstallableUnit> iusWithoutArtifacts = new TreeSet<>();
			for (IInstallableUnit iu : allIUs) {
				Collection<IArtifactKey> artifactKeys = iu.getArtifacts();
				if (artifactKeys.isEmpty()) {
					iusWithoutArtifacts.add(iu);
				} else {
					for (IArtifactKey artifactKey : artifactKeys) {
						artifactIUs.computeIfAbsent(artifactKey, it -> new TreeSet<>()).add(iu);
						String id = iu.getId();
						if (id.endsWith(".feature.jar")) {
							IQuery<IInstallableUnit> iuQuery = QueryUtil.createIUQuery(id.replaceAll(".jar$", ".group"),
									iu.getVersion());
							Set<IInstallableUnit> set = metadataRepository.query(iuQuery, monitor).toSet();
							if (set.size() != 1) {
								if (verbose) {
									System.out.println("featureless-jar=" + iu);
								}
							} else {
								IInstallableUnit feature = set.iterator().next();
								featureJarsToFeatures.put(iu, feature);
								featuresToFeatureJars.put(feature, iu);
							}
						}
					}
				}
			}

			iusWithoutArtifacts.removeAll(featuresToFeatureJars.keySet());

			if (verbose) {
				Set<IArtifactKey> allArtifacts = artifactRepository.query(ArtifactKeyQuery.ALL_KEYS, monitor).toSet();
				for (IArtifactKey key : allArtifacts) {
					if (!artifactIUs.containsKey(key)) {
						System.out.println("artifact-without-ius=" + key);
					}
				}
			}

			Bom bom = new Bom();

			bom.addProperty(createProperty("installable-units-without-artifacts",
					iusWithoutArtifacts.stream().map(IInstallableUnit::getId)));

			ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 4);

			Map<IInstallableUnit, Component> iusToComponents = new LinkedHashMap<>();
			for (var entry : artifactIUs.entrySet()) {
				IArtifactKey artifactKey = entry.getKey();

				Set<IInstallableUnit> ius = entry.getValue();
				IInstallableUnit iu = ius.iterator().next();

				Component component = new Component();
				component.setName(iu.getId());
				component.setType(Component.Type.LIBRARY);
				component.setVersion(iu.getVersion().toString());
				component.setScope(Scope.REQUIRED);

				String name = iu.getProperty(IInstallableUnit.PROP_NAME, null);
				if (name != null) {
					component.setDescription(name);
				}

				String provider = iu.getProperty(IInstallableUnit.PROP_PROVIDER, null);
				if (provider != null) {
					component.setPublisher(provider);
				}

				Map<String, String> properties = iu.getProperties();
				for (var property : properties.entrySet()) {
					Property bomProperty = new Property();
					String key = property.getKey();
					String value = property.getValue();
					if (!"df_LT.license".equals(key) && !"df_LT.copyright".equals(key) && !value.startsWith("%")) {
						bomProperty.setName(key);
						bomProperty.setValue(value);
						component.addProperty(bomProperty);
					}
				}

				IArtifactDescriptor[] artifactDescriptors = artifactRepository.getArtifactDescriptors(artifactKey);
				for (var artifactDescriptor : artifactDescriptors) {
					String format = artifactDescriptor.getProperty(IArtifactDescriptor.FORMAT);
					if (format == null) {
						URI location = artifactRepository.getLocation(artifactDescriptor);
						URI relativeLocation = uri.relativize(location);

						if (relativize) {
							component.setPurl(relativeLocation.toString());
							component.setBomRef(relativeLocation.toString());
						} else {
							component.setPurl(location.toString());
							component.setBomRef(location.toString());
						}

						executor.submit(() -> {
							if (verbose) {
								System.out.println("Processing " + relativeLocation);
							}

							ByteArrayOutputStream out = new ByteArrayOutputStream();
							artifactRepository.getRawArtifact(artifactDescriptor, out, monitor);
							byte[] bytes = out.toByteArray();
							for (String algorithm : ALGORITHMS) {
								Hash hash = new Hash(algorithm, computeHash(algorithm, bytes));
								component.addHash(hash);
							}

							Map<String, String> licenseToName = new TreeMap<>();
							if (bytes.length > 2 && bytes[0] == 0x50 && bytes[1] == 0x4B) {
								processJar(component, bytes, licenseToName);
							}

							if (licenseToName.isEmpty()) {
								MavenDescriptor mavenDescriptor = MavenDescriptor.create(iu);
								if (mavenDescriptor != null) {
									try {
										var content = contentHandler.getContent(URI.create(mavenDescriptor.toURL()));
										processPOM(component, content.getBytes(StandardCharsets.UTF_8), licenseToName);
									} catch (IOException e) {
										//$FALL-THROUGH$
									}
								}
							}

							if (!licenseToName.isEmpty()) {
								LicenseChoice licenseChoice = new LicenseChoice();
								for (var licenseEntry : licenseToName.entrySet()) {
									String licenseName = licenseEntry.getValue();
									String url = licenseEntry.getKey();
									License license = new License();
									if (name != null) {
										license.setName(licenseName);
									}
									license.setUrl(url);
									licenseChoice.addLicense(license);
								}

								component.setLicenseChoice(licenseChoice);
							}
						});

						break;
					}
				}

				bom.addComponent(component);

				iusToComponents.put(iu, component);
			}

			Set<IRequirement> unsatisifiedRequirements = new HashSet<>();

			for (var entry : iusToComponents.entrySet()) {

				IInstallableUnit iu = entry.getKey();
				Component component = entry.getValue();

				IInstallableUnit feature = featureJarsToFeatures.get(iu);
				if (feature != null) {
					iu = feature;
				}

				String componentBomRef = component.getBomRef();
				Dependency dependency = new Dependency(componentBomRef);
				bom.addDependency(dependency);

				for (IRequirement requirement : iu.getRequirements()) {
					int min = requirement.getMin();
					IMatchExpression<IInstallableUnit> matches = requirement.getMatches();
					Set<IInstallableUnit> requiredIUs = metadataRepository
							.query(QueryUtil.createMatchQuery(matches), monitor).toSet();
					if (requiredIUs.isEmpty()) {
						if (min != 0) {
							unsatisifiedRequirements.add(requirement);
						}
					} else {
						for (IInstallableUnit requiredIU : requiredIUs) {
							IInstallableUnit featureJar = featuresToFeatureJars.get(requiredIU);
							Component requiredComponent = iusToComponents
									.get(featureJar == null ? requiredIU : featureJar);
							if (requiredComponent == null) {
								if (!iusWithoutArtifacts.contains(requiredIU)) {
									if (verbose) {
										System.out.println("requirement-not-mapped-to-artifact=" + requiredIU);
									}
								}
							} else {
								String bomRef = requiredComponent.getBomRef();
								if (!componentBomRef.equals(bomRef)) {
									dependency.addDependency(new Dependency(bomRef));
								}
							}
						}
					}
				}
			}

			executor.shutdown();
			try {
				executor.awaitTermination(10, TimeUnit.MINUTES);
			} catch (InterruptedException ex) {
				throw new ProvisionException("Took more than 10 minutes", ex);
			}

			if (verbose) {
				System.out.println("licenes");
				allLicenses.stream().forEach(System.out::println);

				System.out.println();
				System.out.println("rejected-url");
				rejectedURLs.stream().forEach(System.out::println);
			}

			// List<Component> components = bom.getComponents();
			// components.removeIf(it -> it.getLicenseChoice() != null);

			bom.addProperty(createProperty("unsatisfied-requirements",
					unsatisifiedRequirements.stream().map(Object::toString)));

			String xmlOutputArgument = getArgument("-xml-output", args, null);
			String jsonOutputArgument = getArgument("-json-output", args, null);

			boolean json = getArgument("-json", args);
			boolean xml = getArgument("-xml", args) || !json && xmlOutputArgument == null && jsonOutputArgument == null;

			if (xml || xmlOutputArgument != null) {
				try {
					BomXmlGenerator xmlGenerator = createBomXMLGenerator(CycloneDxSchema.Version.VERSION_15, bom);
					String xmlString = xmlGenerator.toXmlString();
					if (xml) {
						System.out.println(xmlString);
					}
					if (xmlOutputArgument != null) {
						Files.writeString(Path.of(xmlOutputArgument), xmlString);
					}
				} catch (Exception ex) {
					throw new RuntimeException(ex);
				}
			}

			if (json || jsonOutputArgument != null) {
				try {
					BomJsonGenerator jsonGenerator = BomGeneratorFactory.createJson(CycloneDxSchema.Version.VERSION_15,
							bom);
					String jsonString = jsonGenerator.toJsonString();
					if (json) {
						System.out.println(jsonString);
					}
					if (jsonOutputArgument != null) {
						Files.writeString(Path.of(jsonOutputArgument), jsonString);

					}
				} catch (Exception ex) {
					throw new RuntimeException(ex);
				}
			}

			return null;
		}

		private void processJar(Component component, byte[] bytes, Map<String, String> licenseToName) {
			try (var zip = new ZipInputStream(new ByteArrayInputStream(bytes))) {
				ZipEntry entry;
				while ((entry = zip.getNextEntry()) != null) {
					String name = entry.getName();
					if (MAVEN_POM_PATTERN.matcher(name).matches()) {
						byte[] allBytes = zip.readAllBytes();
						processPOM(component, allBytes, licenseToName);
					} else if ("about.html".equals(name)) {
						byte[] allBytes = zip.readAllBytes();
						processAboutHTML(component, allBytes, licenseToName);
					} else if (EPL_20_NAME_PATTERN.matcher(name).matches()) {
						licenseToName.put("https://www.eclipse.org/legal/epl-v20.html", "EPL-2.0");
					}
					zip.closeEntry();
				}
			} catch (Exception ex) {
				throw new RuntimeException(ex);
			}
		}

		private void processAboutHTML(Component component, byte[] bytes, Map<String, String> licenseToName) {
			String content = new String(bytes, StandardCharsets.UTF_8);
			List<String> urls = new ArrayList<>();
			for (Matcher matcher = POTENTIAL_LICENSE_REFERENCE_PATTERN.matcher(content); matcher.find();) {
				String url = "https://" + matcher.group(1);
				if (REJECTED_LICENSE_URL_PATTERN.matcher(url).matches()) {
					allLicenses.add(url);
					urls.add(url);
				} else {
					rejectedURLs.add(url);
				}
			}

			for (String url : urls) {
				String old = licenseToName.put(url, null);
				if (old != null) {
					licenseToName.put(url, old);
				}
			}
		}

		private void processPOM(Component component, byte[] bytes, Map<String, String> licenseToName) {
			try {
				var builder = factory.newDocumentBuilder();
				Document document = builder.parse(new InputSource(new ByteArrayInputStream(bytes)));

				List<Element> licenses = evaluate(document, "//pom:license");
				if (!licenses.isEmpty()) {
					for (Element element : licenses) {
						String name = getText(element, "name");
						String url = getText(element, "url");
						licenseToName.put(url, name);
					}
				}

				List<Element> scms = evaluate(document, "//pom:scm/pom:url");
				for (Element element : scms) {
					String url = element.getTextContent();
					if (url != null) {
						ExternalReference externalReference = new ExternalReference();
						externalReference.setType(ExternalReference.Type.VCS);
						externalReference.setUrl(url);
						component.addExternalReference(externalReference);
					}
				}
			} catch (ParserConfigurationException | SAXException | IOException ex) {
				throw new RuntimeException(ex);
			}
		}
	}
}
