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

import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.ArgumentUtil.getArgument;
import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.ArgumentUtil.getArguments;
import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.BOMUtil.addExternalReference;
import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.BOMUtil.computeHash;
import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.BOMUtil.createBomXMLGenerator;
import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.BOMUtil.createProperty;
import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.BOMUtil.urlEncodeQueryParameter;
import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.XMLUtil.evaluate;
import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.XMLUtil.getText;
import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.XMLUtil.newDocumentBuilder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.cyclonedx.Version;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.generators.xml.BomXmlGenerator;
import org.cyclonedx.model.Annotation;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Component.Scope;
import org.cyclonedx.model.Component.Type;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.License;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.Property;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.MultiStatus;
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
import org.eclipse.equinox.p2.metadata.MetadataFactory;
import org.eclipse.equinox.p2.metadata.MetadataFactory.InstallableUnitDescription;
import org.eclipse.equinox.p2.publisher.actions.JREAction;
import org.eclipse.equinox.p2.query.QueryUtil;
import org.eclipse.equinox.p2.repository.ICompositeRepository;
import org.eclipse.equinox.p2.repository.artifact.IArtifactDescriptor;
import org.eclipse.equinox.p2.repository.artifact.IArtifactRepositoryManager;
import org.eclipse.equinox.p2.repository.artifact.spi.ArtifactDescriptor;
import org.eclipse.equinox.p2.repository.metadata.IMetadataRepository;
import org.eclipse.equinox.p2.repository.metadata.IMetadataRepositoryManager;
import org.eclipse.osgi.util.ManifestElement;
import org.json.JSONObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.ctc.wstx.stax.WstxOutputFactory;

@SuppressWarnings("restriction")
public class SBOMApplication implements IApplication {

	private static final Comparator<IArtifactKey> ARTIFACT_COMPARATOR = (o1, o2) -> {
		var result = o1.getClassifier().compareTo(o2.getClassifier());
		if (result == 0) {
			result = o1.getId().compareTo(o2.getId());
			if (result == 0) {
				result = o1.getVersion().compareTo(o2.getVersion());
			}
		}
		return result;
	};

	private static final Pattern MAVEN_POM_PATTERN = Pattern.compile("META-INF/maven/[^/]+/[^/]+/pom.xml");

	private static final Pattern META_INF_FILE_PATTERN = Pattern.compile("META-INF/[^/]+");

	private static final Pattern LICENSE_FILE_PATTERN = Pattern.compile("(.*/)?LICENSE[^/]*(\\.txt)?$");

	private static final Pattern BUNDLE_PROPERTIES_PATTERN = Pattern.compile("(.*/)?(bundle|plugin).properties$");

	private static final XPathFactory XPATH_FACTORY = XPathFactory.newInstance();

	private static final List<String> ALGORITHMS = List.of("MD5", "SHA-1", "SHA-256", "SHA-512", "SHA-384", "SHA3-256",
			"SHA3-384", "SHA3-512");

	private static final Collector<CharSequence, ?, String> INDENTED_PROPERTY_VALUE_COLLECTOR = Collectors
			.joining("\n      ", "\n      ", "\n    ");

	private static final String METADATA_ARTIFACT = "metadata";

	private static boolean isMetadata(IArtifactDescriptor artifactDescriptor) {
		return METADATA_ARTIFACT.equals(artifactDescriptor.getArtifactKey().getClassifier());
	}

	@Override
	public Object start(IApplicationContext context) throws Exception {
		new SBOMGenerator(context).run(new NullProgressMonitor());
		return null;
	}

	public void stop() {
	}

	private static class SBOMGenerator extends AbstractApplication {

		private static final char ZERO_WIDTH_SPACE = '\u200B';

		private static final String A_JRE_JAVASE_ID = "a.jre.javase";

		private static final Pattern ACCEPTED_LICENSE_URL_PATTERN = Pattern
				.compile(".*(documents/epl-v10|epl-v20|legal|license|/MPL).*[^/]", Pattern.CASE_INSENSITIVE);

		private static final Pattern POTENTIAL_LICENSE_REFERENCE_PATTERN = Pattern
				.compile("href=['\"]https?://(.*?)[/\r\n ]*['\"]");

		private static final Pattern EPL_10_NAME_PATTERN = Pattern.compile("epl-?(1.0|v10).*.html?");

		private static final Pattern EPL_20_NAME_PATTERN = Pattern.compile("epl-?(2.0|v20).*.html?");

		private static final Pattern EDL_10_NAME_PATTERN = Pattern.compile("edl-?(1.0|v10).*.html?");

		private static final Pattern APACHE_PUBLIC_LICENSE_20_PATTERN = Pattern.compile(
				"Apache License\\s+\\*?\\s*Version 2.0, January 2004\\s+\\*?\\s*http://www.apache.org/licenses/");

		private static final Pattern GPL_21_PATTERN = Pattern
				.compile("\\s*GNU LESSER GENERAL PUBLIC LICENSE\\s+Version 2\\.1, February 1999");

		private static final Pattern SPDX_ID_PATTERN = Pattern
				.compile("SPDX-License-Identifier:\\s((with\r?\n|[^\r\n\"\\\\|#])+)");

		private static final Pattern FEATURE_JAR_PATTERN = Pattern.compile("(.*\\.feature)\\.jar");

		private static final Pattern SOURCE_IU_PATTERN = Pattern.compile("(.*)\\.source(\\.feature\\.group|)");

		private static final Pattern GITHUB_SCM_PATTERN = Pattern
				.compile("(scm:)?(git:)?https?://github\\.com/(?<repo>[^/]+/[^/]+?)(\\.git)?");

		private final Set<String> rejectedURLs = new TreeSet<>();

		private final Set<String> allLicenses = new TreeSet<>();

		private final Set<IMetadataRepository> metadataRepositories = new LinkedHashSet<>();

		private final Map<IArtifactKey, IInstallableUnit> artifactIUs = new TreeMap<>(ARTIFACT_COMPARATOR);

		private final Map<IArtifactKey, IArtifactDescriptor> artifactDescriptors = new HashMap<>();

		private final Map<IInstallableUnit, IInstallableUnit> featureJarsToFeatures = new HashMap<>();

		private final Map<IInstallableUnit, IInstallableUnit> featuresToFeatureJars = new HashMap<>();

		private final Map<IInstallableUnit, Component> iuComponents = new LinkedHashMap<>();

		private final ContentHandler contentHandler;

		private final SPDXIndex spdxIndex;

		private final boolean verbose;

		private final String input;

		private final boolean xml;

		private final String xmlOutput;

		private final boolean json;

		private final String jsonOutput;

		private IMetadataRepositoryManager metadataRepositoryManager;

		private IArtifactRepositoryManager artifactRepositoryManager;

		private SBOMGenerator(IApplicationContext context) throws Exception {
			var args = getArguments(context);

			contentHandler = new ContentHandler(getArgument("-cache", args, null));
			spdxIndex = new SPDXIndex(contentHandler);

			verbose = getArgument("-verbose", args);
			input = getArgument("-input", args, null);
			xmlOutput = getArgument("-xml-output", args, null);
			jsonOutput = getArgument("-json-output", args, null);
			json = getArgument("-json", args);
			xml = getArgument("-xml", args) || !json && xmlOutput == null && jsonOutput == null;
		}

		@Override
		protected IMetadataRepositoryManager getMetadataRepositoryManager() {
			if (metadataRepositoryManager == null) {
				metadataRepositoryManager = super.getMetadataRepositoryManager();
			}
			return metadataRepositoryManager;
		}

		@Override
		protected IArtifactRepositoryManager getArtifactRepositoryManager() {
			if (artifactRepositoryManager == null) {
				artifactRepositoryManager = super.getArtifactRepositoryManager();
			}
			return artifactRepositoryManager;
		}

		@Override
		public IStatus run(IProgressMonitor monitor) throws ProvisionException {
			if (input == null) {
				System.err.println("An '-input' argument is required");
				return Status.CANCEL_STATUS;
			}

			loadRepositories(monitor);

			buildArtifactMappings();

			var bom = new Bom();

			var randomUUID = UUID.randomUUID();
			bom.setSerialNumber("urn:uuid:" + randomUUID);

			var executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 4);
			var futures = new LinkedHashSet<Future<?>>();

			// Build the basic component information available without I/O.
			var iusToDependencies = new LinkedHashMap<IInstallableUnit, Dependency>();
			for (var entry : artifactIUs.entrySet()) {
				var iu = entry.getValue();
				var component = createComponent(iu);
				iuComponents.put(iu, component);
				bom.addComponent(component);

				var artifactDescriptor = artifactDescriptors.get(entry.getKey());
				var bomRef = setBomRef(component, artifactDescriptor);

				var dependency = new Dependency(bomRef);
				bom.addDependency(dependency);
				iusToDependencies.put(iu, dependency);
			}

			// Gather details from the actual artifacts in parallel.
			for (var entry : artifactIUs.entrySet()) {
				var iu = entry.getValue();
				var component = iuComponents.get(iu);
				var artifactDescriptor = artifactDescriptors.get(entry.getKey());
				futures.add(executor.submit(() -> {
					if (verbose) {
						System.out.println("Processing " + component.getBomRef());
					}

					var bytes = getArtifactContent(component, artifactDescriptor);
					setPurl(component, iu, artifactDescriptor, bytes);
					gatherLicences(component, iu, artifactDescriptor, bytes);

					resolveDependencies(iusToDependencies.get(iu), iu);
				}));
			}

			executor.shutdown();
			try {
				executor.awaitTermination(10, TimeUnit.MINUTES);
				var multiStatus = new MultiStatus(getClass(), 0, "Problems");
				for (var future : futures) {
					try {
						future.get();
					} catch (ExecutionException e) {
						multiStatus.add(new Status(IStatus.ERROR, getClass(), e.getMessage(), e));
					}
				}

				if (!multiStatus.isOK()) {
					throw new ProvisionException(multiStatus);
				}

			} catch (InterruptedException ex) {
				throw new ProvisionException("Took more than 10 minutes", ex);
			}

			// Transfer gathered details from binary IU to corresponding source IU.
			for (var entry : iuComponents.entrySet()) {
				IInstallableUnit iu = entry.getKey();
				Component component = entry.getValue();
				transferDetailsFromBinaryToSource(component, iu);
			}

			if (verbose) {
				System.out.println("licenes");
				allLicenses.stream().forEach(System.out::println);

				System.out.println();
				System.out.println("rejected-url");
				rejectedURLs.stream().forEach(System.out::println);
			}

			generateXML(bom);
			generateJson(bom);

			return Status.OK_STATUS;
		}

		private void buildArtifactMappings() {
			var metadataRepositoryManager = getMetadataRepositoryManager();
			var artifactRepository = getCompositeArtifactRepository();
			for (var iu : metadataRepositoryManager.query(QueryUtil.ALL_UNITS, null).toSet()) {
				if ("true".equals(iu.getProperty(QueryUtil.PROP_TYPE_CATEGORY)) || //
						A_JRE_JAVASE_ID.equals(iu.getId())) {
					continue;
				}

				var artifactKeys = iu.getArtifacts();
				if (artifactKeys.isEmpty()) {
					associate(iu, createMetadataArtifactDecriptor(iu));
				} else {
					for (var artifactKey : artifactKeys) {
						for (var artifactDescriptor : artifactRepository.getArtifactDescriptors(artifactKey)) {
							// Only process the canonical descriptor, i.e., not the pack200.
							String format = artifactDescriptor.getProperty(IArtifactDescriptor.FORMAT);
							if (format == null) {
								associate(iu, artifactDescriptor);

								// Create the two-way map between feature IU and feature jar IU.
								var id = iu.getId();

								Matcher matcher = FEATURE_JAR_PATTERN.matcher(id);
								if (matcher.matches()) {
									var iuQuery = QueryUtil.createIUQuery(matcher.group(1) + ".group", iu.getVersion());
									var set = metadataRepositoryManager.query(iuQuery, null).toSet();
									if (set.size() != 1) {
										if (verbose) {
											System.err.println("featureless-jar=" + iu);
										}
									} else {
										var feature = set.iterator().next();
										featureJarsToFeatures.put(iu, feature);
										featuresToFeatureJars.put(feature, iu);
									}
								}

								break;
							}
						}
					}
				}
			}
		}

		private void loadRepositories(IProgressMonitor monitor) throws ProvisionException {
			var uri = URI.create(input);

			var repositoryDescriptor = new RepositoryDescriptor();
			repositoryDescriptor.setLocation(uri);
			addSource(repositoryDescriptor);

			var metadataRepositoryManager = getMetadataRepositoryManager();
			metadataRepositoryManager.loadRepository(uri, monitor);

			var artifactRepositoryManager = getArtifactRepositoryManager();
			artifactRepositoryManager.loadRepository(uri, monitor);

			metadataRepositories.addAll(
					gatherSimpleRepositories(new HashSet<>(), new TreeMap<>(), getCompositeMetadataRepository()));

			if (metadataRepositoryManager.query(QueryUtil.createIUQuery(A_JRE_JAVASE_ID), null).isEmpty()) {
				var jreIU = JREAction.createJREIU();
				try {
					var jres = Files.createTempDirectory("jres");
					jres.toFile().deleteOnExit();
					var jresRepository = metadataRepositoryManager.createRepository(jres.toUri(), "JREs",
							IMetadataRepositoryManager.TYPE_SIMPLE_REPOSITORY, Map.of());
					jresRepository.addInstallableUnits(List.of(jreIU));
				} catch (IOException e) {
					throw new ProvisionException("Cannot create temp folder: ", e);
				}
			}
		}

		private Collection<IMetadataRepository> gatherSimpleRepositories(Set<IMetadataRepository> visited,
				Map<URI, IMetadataRepository> repositories, IMetadataRepository repository) throws ProvisionException {
			if (visited.add(repository)) {
				if (repository instanceof ICompositeRepository<?> composite) {
					var children = composite.getChildren();
					for (var child : children) {
						var childRepository = getMetadataRepositoryManager().loadRepository(child, null);
						gatherSimpleRepositories(visited, repositories, childRepository);
					}
				} else {
					repositories.put(repository.getLocation(), repository);
				}
			}
			return repositories.values();
		}

		private IArtifactDescriptor createMetadataArtifactDecriptor(IInstallableUnit iu) {
			var artifactRepository = getCompositeArtifactRepository();
			var artifactKey = artifactRepository.createArtifactKey(METADATA_ARTIFACT, iu.getId(), iu.getVersion());
			var artifactDescriptor = (ArtifactDescriptor) artifactRepository.createArtifactDescriptor(artifactKey);
			artifactDescriptor.setRepository(artifactRepository);

			for (var metadataRepository : metadataRepositories) {
				if (metadataRepository.contains(iu)) {
					artifactDescriptor.setProperty("location", metadataRepository.getLocation().toString());
					return artifactDescriptor;
				}
			}

			throw new RuntimeException("Not location for " + iu);
		}

		private void associate(IInstallableUnit iu, IArtifactDescriptor artifactDescriptor) {
			var artifactKey = artifactDescriptor.getArtifactKey();
			artifactIUs.put(artifactKey, iu);
			artifactDescriptors.put(artifactKey, artifactDescriptor);
		}

		private Component createComponent(IInstallableUnit iu) {
			var component = new Component();
			component.setName(iu.getId());
			component.setType(Component.Type.LIBRARY);
			component.setVersion(iu.getVersion().toString());
			component.setScope(Scope.REQUIRED);

			var name = iu.getProperty(IInstallableUnit.PROP_NAME, null);
			var description = iu.getProperty(IInstallableUnit.PROP_DESCRIPTION, null);
			if (description != null) {
				// Use ZERO_WIDTH_SPACE as a marker for rendering the description separately
				// from the name.
				component.setDescription(name == null ? "" : name + " - " + ZERO_WIDTH_SPACE + description);
			} else if (name != null) {
				component.setDescription(name);
			}

			var provider = iu.getProperty(IInstallableUnit.PROP_PROVIDER, null);
			if (provider != null) {
				component.setPublisher(provider);
			}

			var docURL = iu.getProperty(IInstallableUnit.PROP_DOC_URL, null);
			if (docURL != null && docURL.startsWith("http")) {
				addExternalReference(component, ExternalReference.Type.WEBSITE, docURL);
			}

			var descriptionURL = iu.getProperty(IInstallableUnit.PROP_DESCRIPTION_URL, null);
			if (descriptionURL != null && descriptionURL.startsWith("http")) {
				addExternalReference(component, ExternalReference.Type.WEBSITE, descriptionURL);
			}

			for (var property : iu.getProperties().entrySet()) {
				String key = property.getKey();
				String value = property.getValue();
				// Filter properties that will be reflected elsewhere in the gathered details,
				// or are not relevant.
				if (!key.startsWith("df_LT") && !key.startsWith("maven-") && !IInstallableUnit.PROP_NAME.equals(key)
						&& !"org.eclipse.justj.model".equals(key) && !"org.eclipse.update.feature.plugin".equals(key)
						&& !MetadataFactory.InstallableUnitDescription.PROP_TYPE_GROUP.equals(key)
						&& !MetadataFactory.InstallableUnitDescription.PROP_TYPE_FRAGMENT.equals(key)
						&& !MetadataFactory.InstallableUnitDescription.PROP_TYPE_PRODUCT.equals(key)
						&& !IInstallableUnit.PROP_BUNDLE_LOCALIZATION.equals(key)
						&& !IInstallableUnit.PROP_DESCRIPTION.equals(key)
						&& !IInstallableUnit.PROP_DESCRIPTION_URL.equals(key)
						&& !IInstallableUnit.PROP_PROVIDER.equals(key) && !IInstallableUnit.PROP_DOC_URL.equals(key)
						&& !value.startsWith("%")) {
					component.addProperty(createProperty(key, value));
				}
			}

			return component;
		}

		private String setBomRef(Component component, IArtifactDescriptor artifactDescriptor) {
			if (isMetadata(artifactDescriptor)) {
				var artifactKey = artifactDescriptor.getArtifactKey();
				component.setBomRef(METADATA_ARTIFACT + "/" + artifactKey.getId() + '_' + artifactKey.getVersion());
			} else {
				var artifactRepository = (SimpleArtifactRepository) artifactDescriptor.getRepository();
				var artifactLocation = artifactRepository.getLocation(artifactDescriptor);
				var location = artifactRepository.getLocation();
				var relativeLocation = location.relativize(artifactLocation);
				component.setBomRef(relativeLocation.toString());
			}
			return component.getBomRef();
		}

		private void setPurl(Component component, IInstallableUnit iu, IArtifactDescriptor artifactDescriptor,
				byte[] bytes) {
			var mavenDescriptor = MavenDescriptor.create(artifactDescriptor);
			if (mavenDescriptor != null) {
				try {
					// Document xmlContent =
					// contentHandler.getXMLContent(mavenDescriptor.toPOMURI());
					byte[] mavenArtifactBytes = contentHandler.getBinaryContent(mavenDescriptor.toArtifactURI());
					String purl = mavenDescriptor.getMavenPURL();
					if (Arrays.equals(bytes, mavenArtifactBytes)) {
						component.setPurl(purl);
						return;
					}
					component.addProperty(BOMUtil.createProperty("wrapped-purl", purl));
				} catch (ContentHandler.ContentHandlerException e) {
					// The only valid reason to fail is a 404,
					// i.e., resource does not exist on Maven Central.
					if (e.getResponse().statusCode() != 404) {
						throw new RuntimeException(e);
					}
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}

			var location = isMetadata(artifactDescriptor) ? URI.create(artifactDescriptor.getProperty("location"))
					: artifactDescriptor.getRepository().getLocation();
			var artifactKey = artifactDescriptor.getArtifactKey();
			var encodedLocation = urlEncodeQueryParameter(location.toString());
			var purl = "pkg:p2/" + artifactKey.getId() + "@" + artifactKey.getVersion() + "?classifier="
					+ artifactKey.getClassifier() + "&location=" + encodedLocation;
			component.setPurl(purl);
		}

		private byte[] getArtifactContent(Component component, IArtifactDescriptor artifactDescriptor) {
			var isMetadata = isMetadata(artifactDescriptor);
			byte[] bytes;
			if (isMetadata) {
				bytes = new byte[0];
				component.setType(Type.DATA);
			} else {
				var out = new ByteArrayOutputStream();
				getCompositeArtifactRepository().getRawArtifact(artifactDescriptor, out, new NullProgressMonitor());
				bytes = out.toByteArray();

				for (String algorithm : ALGORITHMS) {
					component.addHash(new Hash(algorithm, computeHash(algorithm, bytes)));
				}
			}
			return bytes;
		}

		private void gatherLicences(Component component, IInstallableUnit iu, IArtifactDescriptor artifactDescriptor,
				byte[] bytes) {
			var licenseToName = new TreeMap<String, String>();
			if (bytes.length > 2 && bytes[0] == 0x50 && bytes[1] == 0x4B) {
				gatherLicencesFromJar(component, bytes, licenseToName);
			}

			var mavenDescriptor = MavenDescriptor.create(artifactDescriptor);
			if (mavenDescriptor != null) {
				try {
					var content = contentHandler.getContent(mavenDescriptor.toPOMURI());
					gatherInformationFromPOM(component, content.getBytes(StandardCharsets.UTF_8), licenseToName);
				} catch (ContentHandler.ContentHandlerException e) {
					if (e.getResponse().statusCode() != 404) {
						throw new RuntimeException(e);
					}
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}

			var licenses = iu.getLicenses(null);
			for (var license : licenses) {
				var location = license.getLocation();
				if (location != null) {
					var value = location.toString();
					if (!value.startsWith("%")) {
						licenseToName.putIfAbsent(value, null);
					}
				}
			}

			if (!licenseToName.isEmpty()) {
				var licenseChoice = new LicenseChoice();
				for (var licenseEntry : licenseToName.entrySet()) {
					var licenseName = licenseEntry.getValue();
					var url = licenseEntry.getKey();
					var license = new License();
					if (licenseName != null) {
						license.setName(licenseName);
					}
					license.setUrl(url);
					licenseChoice.addLicense(license);
				}
				component.setLicenses(licenseChoice);
			}
		}

		private void gatherLicencesFromJar(Component component, byte[] bytes, Map<String, String> licenseToName) {
			try (var zip = new ZipInputStream(new ByteArrayInputStream(bytes))) {
				ZipEntry entry;
				while ((entry = zip.getNextEntry()) != null) {
					var name = entry.getName();
					if ("META-INF/MANIFEST.MF".equals(name)) {
						var allBytes = zip.readAllBytes();
						// String contents = new String(allBytes, StandardCharsets.UTF_8);
						var headers = ManifestElement.parseBundleManifest(new ByteArrayInputStream(allBytes));

						var bundleLicense = headers.get("Bundle-License");
						if ("Eclipse Public License v2.0".equals(bundleLicense)
								|| "Eclipse Public License, Version 2.0;link=\"http://www.eclipse.org/legal/epl-2.0\""
										.equals(bundleLicense)) {
							licenseToName.put("https://www.eclipse.org/legal/epl-v20.html", "EPL-2.0");
						} else if ("Eclipse Public License v1.0".equals(bundleLicense)) {
							licenseToName.put("https://www.eclipse.org/legal/epl-v10.html", "EPL-1.0");
						} else if ("The Apache License, Version 2.0".equals(bundleLicense)) {
							licenseToName.put("https://www.apache.org/licenses/LICENSE-2.0", "Apache-2.0");
						} else if (bundleLicense != null) {
							if ("Apache License, Version 2.0; see: http://www.apache.org/licenses/LICENSE-2.0.txt"
									.equals(bundleLicense)) {
								bundleLicense = "Apache-2.0;location=http://www.apache.org/licenses/LICENSE-2.0.txt";
							}
							var bundleLicenseElements = ManifestElement.parseHeader("Bundle-License", bundleLicense);
							for (var bundleLicenseElement : bundleLicenseElements) {
								var value = bundleLicenseElement.getValue();
								var linkAttribute = bundleLicenseElement.getAttribute("link");
								if (linkAttribute != null) {
									var links = linkAttribute.split(" *, *");
									for (var link : links) {
										licenseToName.put(link, value);
									}
								} else {
									if (value.startsWith("://")) {
										value = "https" + value;
									} else if ("jquery.com/license/".equals(value)
											|| "jquery.org/license".equals(value)) {
										value = "https://" + value;
									}
									if (!value.startsWith("http")) {
										var license = spdxIndex.getLicense(value);
										if (license != null) {
											licenseToName.put(license, value);
										} else {
											System.err.println("###");
										}
									} else {
										licenseToName.put(value, null);
									}
								}
							}
						}

						var bundleDoc = headers.get("Bundle-DocURL");
						if (bundleDoc != null && bundleDoc.startsWith("http")) {
							addExternalReference(component, ExternalReference.Type.WEBSITE, bundleDoc);
						}

						var eclipseSourceReferences = headers.get("Eclipse-SourceReferences");
						if (eclipseSourceReferences != null) {
							var eclipseSourceReferenceElements = ManifestElement.parseHeader("Eclipse-SourceReferences",
									eclipseSourceReferences);
							for (var eclipseSourceReferenceElement : eclipseSourceReferenceElements) {
								var value = eclipseSourceReferenceElement.getValue();
								var query = Collections.list(eclipseSourceReferenceElement.getKeys()).stream()
										.map(key -> (key + '='
												+ urlEncodeQueryParameter(
														eclipseSourceReferenceElement.getAttribute(key))))
										.collect(Collectors.joining("&", "?", ""));
								addExternalReference(component, ExternalReference.Type.VCS, value + query);

								Matcher matcher = GITHUB_SCM_PATTERN.matcher(value);
								if (matcher.matches()) {
									var uri = URI.create("https://github.com/" + matcher.group("repo") + "/issues");
									if (contentHandler.exists(uri)) {
										addExternalReference(component, ExternalReference.Type.ISSUE_TRACKER,
												uri.toString());
									}
								}
							}
						}
					} else if (MAVEN_POM_PATTERN.matcher(name).matches()) {
						var allBytes = zip.readAllBytes();
						gatherInformationFromPOM(component, allBytes, licenseToName);
					} else if ("about.html".equals(name)) {
						var allBytes = zip.readAllBytes();
						gatherLicencesFromAbout(component, allBytes, licenseToName);
					} else if (EDL_10_NAME_PATTERN.matcher(name).matches()) {
						licenseToName.put("https://www.eclipse.org/org/documents/edl-v10.html", "EDL-1.0");
					} else if (EPL_20_NAME_PATTERN.matcher(name).matches()) {
						licenseToName.put("https://www.eclipse.org/legal/epl-v20.html", "EPL-2.0");
					} else if (EPL_10_NAME_PATTERN.matcher(name).matches()) {
						licenseToName.put("https://www.eclipse.org/legal/epl-v10.html", "EPL-1.0");
					} else if (META_INF_FILE_PATTERN.matcher(name).matches()) {
						if (!name.endsWith(".RSA") && !name.endsWith(".SF") && !name.endsWith(".inf")
								&& !name.endsWith(".DSA") && !name.endsWith("DEPENDENCIES")) {
							var allBytes = zip.readAllBytes();
							gatherLicencesFromFile(allBytes, licenseToName);
						}
					} else if (BUNDLE_PROPERTIES_PATTERN.matcher(name).matches()) {
						var allBytes = zip.readAllBytes();
						gatherLicencesFromFile(allBytes, licenseToName);
					} else if (LICENSE_FILE_PATTERN.matcher(name).matches()) {
						var allBytes = zip.readAllBytes();
						gatherLicencesFromFile(allBytes, licenseToName);
					}
					zip.closeEntry();
				}
			} catch (Exception ex) {
				throw new RuntimeException(ex);
			}
		}

		private void gatherLicencesFromFile(byte[] bytes, Map<String, String> licenseToName) {
			var content = new String(bytes, StandardCharsets.UTF_8);
			if (APACHE_PUBLIC_LICENSE_20_PATTERN.matcher(content).find()) {
				licenseToName.put("https://www.apache.org/licenses/LICENSE-2.0", "Apache-2.0");
			} else if (GPL_21_PATTERN.matcher(content).find()) {
				licenseToName.put("https://spdx.org/licenses/LGPL-2.1-only.html", "LGPL-2.1-only");
			} else if (content.contains("The Apache Software License, Version 1.1")) {
				licenseToName.put("http://www.apache.org/licenses/LICENSE-1.1", "Apache-1.1");
			} else if (content.startsWith("BSD License")) {
				licenseToName.put("https://spdx.org/licenses/0BSD.html", "0BSD");
			} else if (content.startsWith("# Eclipse Public License - v 2.0")
					|| content.startsWith("Eclipse Public License - v 2.0")) {
				licenseToName.put("https://www.eclipse.org/legal/epl-v20.html", "EPL-2.0");
			} else if (content.contains("IBM Public License Version 1.0")) {
				licenseToName.put("https://spdx.org/licenses/IPL-1.0.html", "IBM Public License v1.0");
			} else {
				// SPDX-License-Identifier: BSD-3-Clause
				var matcher = SPDX_ID_PATTERN.matcher(content);
				if (matcher.find()) {
					do {
						var spdxId = matcher.group(1).trim();
						var license = spdxIndex.getLicense(spdxId);
						if (license != null) {
							licenseToName.put(license, spdxId);
						} else {
							var parts = spdxId.replaceAll("[()]", "")
									.split("\\s+OR\\s+|\\s+AND\\s+|\\s+WITH\\s+|\\s+with\\s+");
							if (parts.length > 1) {
								for (var part : parts) {
									license = spdxIndex.getLicense(part);
									if (license != null) {
										licenseToName.put(license, spdxId);
									} else {
										System.err.println("####?>>'" + part + "'");
									}
								}
							} else {
								System.err.println("####?>'" + spdxId + "'");
							}
						}
					} while (matcher.find());
				} else {
					// System.err.println("###");
				}
			}
		}

		private void gatherLicencesFromAbout(Component component, byte[] bytes, Map<String, String> licenseToName) {
			var content = new String(bytes, StandardCharsets.UTF_8);
			var urls = new ArrayList<String>();
			for (var matcher = POTENTIAL_LICENSE_REFERENCE_PATTERN.matcher(content); matcher.find();) {
				var url = "https://" + matcher.group(1);
				if (ACCEPTED_LICENSE_URL_PATTERN.matcher(url).matches()) {
					allLicenses.add(url);
					urls.add(url);
				} else if (!url.endsWith(".xsd") && !url.endsWith(".dtd")) {
					rejectedURLs.add(url);
				}
			}

			for (var url : urls) {
				var old = licenseToName.put(url, null);
				if (old != null) {
					licenseToName.put(url, old);
				}
			}

			if (content.indexOf("Eclipse Distribution License - v 1.0") != -1
					|| content.indexOf("Eclipse Distribution License - Version 1.0") != -1) {
				licenseToName.put("https://www.eclipse.org/org/documents/edl-v10.html", "edl-v10");
			}

			if (content.indexOf("Eclipse Public License Version 2.0") != -1) {
				licenseToName.put("https://www.eclipse.org/legal/epl-v20.html", "EPL-2.0");
			}
		}

		private void gatherInformationFromPOM(Component component, byte[] bytes, Map<String, String> licenseToName) {
			try {
				var builder = newDocumentBuilder();
				var document = builder.parse(new InputSource(new ByteArrayInputStream(bytes)));
				gatherInformationFromPOM(component, document, licenseToName);
			} catch (RuntimeException ex) {
				throw ex;
			} catch (ParserConfigurationException | SAXException | IOException ex) {
				throw new RuntimeException(ex);
			}
		}

		private void gatherInformationFromPOM(Component component, Document document,
				Map<String, String> licenseToName) {
			var licenses = evaluate(document, "//pom:license|//license");
			if (!licenses.isEmpty()) {
				for (var element : licenses) {
					var name = getText(element, "name");
					var url = getText(element, "url");
					if (url == null) {
						if (name == null) {
							continue;
						}
						var spdxLicense = spdxIndex.getLicense(name);
						if (spdxLicense == null) {
							spdxLicense = name;
						}
						url = spdxLicense;
					}
					var parts = url.split(" *, *");
					for (var part : parts) {
						licenseToName.put(part, name);
					}
				}
			}

			var scms = evaluate(document, "//pom:scm|//scm");
			for (var element : scms) {
				var connection = getText(element, "connection");
				if (connection == null) {
					connection = getText(element, "developerConnection");
					if (connection == null) {
						connection = getText(element, "url");
					}
				}
				if (connection != null) {
					addExternalReference(component, ExternalReference.Type.VCS, connection);
				}
			}

			var issues = evaluate(document, "//pom:issueManagement|//issueManagement");
			for (var element : issues) {
				var url = getText(element, "url");
				if (url != null) {
					addExternalReference(component, ExternalReference.Type.ISSUE_TRACKER, url);
				}
			}

			var websites = evaluate(document, "//pom:project|//project");
			for (var element : websites) {
				var url = getText(element, "url");
				if (url != null && url.startsWith("http")) {
					addExternalReference(component, ExternalReference.Type.WEBSITE, url);
				}
			}

			var mailingLists = evaluate(document, "//pom:mailingList|//mailingList");
			for (var element : mailingLists) {
				var url = getText(element, "archive");
				if (url == null) {
					url = getText(element, "post");
				}
				if (url != null) {
					addExternalReference(component, ExternalReference.Type.MAILING_LIST, url);
				} else {
					System.err.println("##");
				}
			}

			var distributions = evaluate(document, "//pom:repository|//repository");
			for (var element : distributions) {
				if (element.getParentNode().getLocalName().equals("distributionManagement")) {
					var url = getText(element, "url");
					if (url != null) {
						addExternalReference(component, ExternalReference.Type.DISTRIBUTION, url);
					} else {
						System.err.println("##");
					}
				}
			}
		}

		private void resolveDependencies(Dependency dependency, IInstallableUnit iu) {
			var metadataRepositoryManager = getMetadataRepositoryManager();
			var component = iuComponents.get(iu);
			String componentBomRef = component.getBomRef();

			for (var requirement : iu.getRequirements()) {
				var matches = requirement.getMatches();
				var requiredIUs = metadataRepositoryManager.query(QueryUtil.createMatchQuery(matches), null).toSet();
				if (requiredIUs.isEmpty()) {
					var min = requirement.getMin();
					if (min != 0) {
						component
								.addProperty(BOMUtil.createProperty("unsatisfied-requirement", requirement.toString()));
					}
				} else {
					for (var requiredIU : requiredIUs) {
						var featureJar = featuresToFeatureJars.get(requiredIU);
						var requiredComponent = iuComponents.get(featureJar == null ? requiredIU : featureJar);
						if (requiredComponent == null) {
							if (!requiredIU.getId().startsWith(A_JRE_JAVASE_ID)) {
								if (verbose) {
									System.out.println("requirement-not-mapped-to-artifact=" + requiredIU);
								}
							}
						} else {
							var bomRef = requiredComponent.getBomRef();
							if (!componentBomRef.equals(bomRef)) {
								dependency.addDependency(new Dependency(bomRef));
							}
						}
					}
				}
			}
		}

		private void transferDetailsFromBinaryToSource(Component component, IInstallableUnit iu) {
			var id = iu.getId();
			var matcher = SOURCE_IU_PATTERN.matcher(id);
			if (matcher.matches()) {
				var description = new InstallableUnitDescription();
				description.setId(matcher.group(1) + matcher.group(2));
				description.setVersion(iu.getVersion());
				var binaryIU = MetadataFactory.createInstallableUnit(description);
				var binaryFeatureJarIU = featuresToFeatureJars.get(binaryIU);
				var binaryComponent = iuComponents.get(binaryFeatureJarIU == null ? binaryIU : binaryFeatureJarIU);
				if (binaryComponent != null) {
					var licenseChoice = component.getLicenses();
					if (licenseChoice == null) {
						component.setLicenses(binaryComponent.getLicenses());
					}
					var externalReferences = component.getExternalReferences();
					if (externalReferences == null || externalReferences.isEmpty()) {
						component.setExternalReferences(binaryComponent.getExternalReferences());
					}
				} else {
					System.err.println("## missing binary" + id);
				}
			}
		}

		private void generateXML(Bom bom) {
			if (xml || xmlOutput != null) {
				try {
					var xmlGenerator = createBomXMLGenerator(Version.VERSION_16, bom);
					var xmlString = xmlGenerator.toXmlString();
					if (xml) {
						System.out.println(xmlString);
					}
					if (xmlOutput != null) {
						Files.writeString(Path.of(xmlOutput), xmlString);
					}
				} catch (Exception ex) {
					throw new RuntimeException(ex);
				}
			}
		}

		private void generateJson(Bom bom) {
			if (json || jsonOutput != null) {
				try {
					var jsonGenerator = BomGeneratorFactory.createJson(Version.VERSION_16, bom);
					var jsonString = jsonGenerator.toJsonString();
					if (json) {
						System.out.println(jsonString);
					}
					if (jsonOutput != null) {
						Files.writeString(Path.of(jsonOutput), jsonString);

					}
				} catch (Exception ex) {
					throw new RuntimeException(ex);
				}
			}
		}
	}

	public static final class XMLUtil {

		private static final DocumentBuilderFactory FACTORY;

		private XMLUtil() {
		}

		static {
			FACTORY = DocumentBuilderFactory.newInstance();
			FACTORY.setNamespaceAware(true);
			FACTORY.setValidating(false);
			try {
				FACTORY.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
				FACTORY.setFeature("http://xml.org/sax/features/external-general-entities", false);
				FACTORY.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
			} catch (ParserConfigurationException e) {
				throw new RuntimeException(e.getMessage(), e);
			}
		}

		public static DocumentBuilder newDocumentBuilder() throws ParserConfigurationException {
			return FACTORY.newDocumentBuilder();
		}

		public static String getText(Element element, String name) {
			var nodeList = element.getElementsByTagName(name);
			if (nodeList.getLength() > 0) {
				return nodeList.item(0).getTextContent();
			}
			return null;
		}

		public static List<Element> evaluate(Node node, String expression) {
			var xPath = XPATH_FACTORY.newXPath();
			try {
				var document = node instanceof Document doc ? doc : node.getOwnerDocument();
				xPath.setNamespaceContext(new NamespaceContext() {
					@Override
					public String getNamespaceURI(String prefix) {
						if (prefix.equals(XMLConstants.DEFAULT_NS_PREFIX)) {
							return document.lookupNamespaceURI(null);
						}
						var result = document.lookupNamespaceURI(prefix);
						if (result == null) {
							result = document.lookupNamespaceURI(null);
						}
						if (result == null && "pom".equals(prefix)) {
							return "http://maven.apache.org/POM/4.0.0";
						}
						return result;
					}

					@Override
					public Iterator<String> getPrefixes(String val) {
						return null;
					}

					@Override
					public String getPrefix(String namespaceURI) {
						return document.lookupPrefix(namespaceURI);
					}
				});

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
	}

	record MavenDescriptor(String groupId, String artifactId, String version, String classifier, String type) {
		public static MavenDescriptor create(IArtifactDescriptor artifactDescriptor) {
			var mavenDescriptor = create(artifactDescriptor.getProperties());
			if (mavenDescriptor == null && !isMetadata(artifactDescriptor)) {
				// System.err.println("###" + artifactDescriptor);
			}
			return mavenDescriptor;
		}

		public static MavenDescriptor create(Map<String, String> properties) {
			var mavenGroupId = properties.get("maven-groupId");
			if (mavenGroupId == null) {
				mavenGroupId = properties.get("maven-wrapped-groupId");
			}

			var mavenArtifactId = properties.get("maven-artifactId");
			if (mavenArtifactId == null) {
				mavenArtifactId = properties.get("maven-wrapped-artifactId");
			}

			var mavenVersion = properties.get("maven-version");
			if (mavenVersion == null) {
				mavenVersion = properties.get("maven-wrapped-version");
			}

			var mavenClassifier = properties.get("maven-classifier");
			if (mavenClassifier == null) {
				mavenClassifier = properties.get("maven-wrapped-classifier");
			}

			var mavenType = properties.get("maven-type");
			if (mavenType == null) {
				mavenType = properties.get("maven-wrapped-type");
			}

			if (mavenGroupId != null && mavenArtifactId != null && mavenVersion != null) {
				return new MavenDescriptor(mavenGroupId, mavenArtifactId, mavenVersion,
						mavenClassifier == null || mavenClassifier.isBlank() ? null : mavenClassifier,
						mavenType == null || mavenType.isBlank() ? "jar" : mavenType);
			}

			return null;
		}

		public URI toPOMURI() {
			return toURI(".pom");
		}

		public URI toArtifactURI() {
			return toURI((classifier == null ? "" : '-' + classifier) + "." + type);
		}

		public String getMavenPURL() {
			var qualifiers = new LinkedHashMap<String, String>();
			if (!"jar".equals(type)) {
				qualifiers.put("type", type);
			}
			if (classifier != null) {
				qualifiers.put("classifier", classifier);
			}
			var query = qualifiers.isEmpty() ? ""
					: qualifiers.entrySet().stream().map(Object::toString).collect(Collectors.joining("&", "?", ""));
			return "pkg:maven/" + groupId + '/' + artifactId + '@' + version + query;
		}

		private URI toURI(String suffix) {
			return URI.create("https://repo.maven.apache.org/maven2/" + groupId.replace('.', '/') + "/" + artifactId
					+ "/" + version + "/" + artifactId + "-" + version + suffix);
		}
	}

	public final static class SPDXIndex {

		private final Map<String, String> spdxLicenceIds = new TreeMap<String, String>();

		private final Map<String, String> spdxLicenceNames = new TreeMap<String, String>();

		public SPDXIndex(ContentHandler contentHandler) {
			try {
				buildSPDXIndex(contentHandler);
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		private void buildSPDXIndex(ContentHandler contentHandler) throws IOException {
			buildSPDXIndex(contentHandler.getContent(URI.create("https://spdx.org/licenses/licenses.json")),
					"licenses");
			buildSPDXIndex(contentHandler.getContent(URI.create("https://spdx.org/licenses/exceptions.json")),
					"exceptions");
		}

		@SuppressWarnings("unchecked")
		private void buildSPDXIndex(String licenses, String property) {
			var jsonArray = new JSONObject(licenses).getJSONArray(property);
			for (var license : (Iterable<JSONObject>) (Iterable<?>) jsonArray) {
				var reference = license.getString("reference");

				var id = license.getString("exceptions".equals(property) ? "licenseExceptionId" : "licenseId");
				spdxLicenceIds.put(id, reference);

				var name = license.getString("name");
				spdxLicenceNames.put(name, reference);
			}
		}

		public String getLicense(String nameOrId) {
			var license = spdxLicenceIds.get(nameOrId);
			if (license == null) {
				license = spdxLicenceNames.get(nameOrId);
			}
			return license;
		}
	}

	public static class ContentHandler {

		public static class ContentHandlerException extends IOException {
			private static final long serialVersionUID = 1L;

			private final HttpResponse<?> response;

			public ContentHandlerException(HttpResponse<?> response) {
				super("status code " + response.statusCode() + " -> " + response.uri());
				this.response = response;
			}

			public HttpResponse<?> getResponse() {
				return response;
			}
		}

		private final Map<URI, Boolean> exists = new ConcurrentHashMap<>();

		private final Path cache;

		private final HttpClient httpClient;

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

		protected <T> T basicGetContent(URI uri, BodyHandler<T> bodyHandler) throws IOException, InterruptedException {
			var requestBuilder = HttpRequest.newBuilder(uri).GET();
			var request = requestBuilder.build();
			var response = httpClient.send(request, bodyHandler);
			var statusCode = response.statusCode();
			if (statusCode != 200) {
				throw new ContentHandlerException(response);
			}
			return response.body();
		}

		protected <T> T basicHead(URI uri, BodyHandler<T> bodyHandler) throws IOException, InterruptedException {
			var requestBuilder = HttpRequest.newBuilder(uri).method("HEAD", BodyPublishers.noBody());
			var request = requestBuilder.build();
			var response = httpClient.send(request, bodyHandler);
			var statusCode = response.statusCode();
			if (statusCode != 200) {
				throw new ContentHandlerException(response);
			}
			return response.body();
		}

		protected Path getCachePath(URI uri) {
			var decodedURI = URLDecoder.decode(uri.toString(), StandardCharsets.UTF_8);
			var uriSegments = decodedURI.split("[:/?#&;]+");
			var result = cache.resolve(String.join("/", uriSegments));
			return result;
		}

		interface Reader<T> {
			T read(Path path) throws IOException;
		}

		interface Writer<T> {
			void write(Path path, T t) throws IOException;
		}

		public boolean exists(URI uri) {
			return exists.computeIfAbsent(uri, u -> {
				try {
					basicHead(uri, BodyHandlers.ofString());
					return true;
				} catch (ContentHandlerException e) {
					if (e.getResponse().statusCode() == 404) {
						return false;
					}
					throw new RuntimeException(e);
				} catch (IOException | InterruptedException e) {
					throw new RuntimeException(e);
				}
			});
		}

		public String getContent(URI uri) throws IOException {
			return getContent(uri, Files::readString, Files::writeString, BodyHandlers.ofString());
		}

		public byte[] getBinaryContent(URI uri) throws IOException {
			return getContent(uri, Files::readAllBytes, Files::write, BodyHandlers.ofByteArray());
		}

		public <T> T getContent(URI uri, Reader<T> reader, Writer<T> writer, BodyHandler<T> bodyHandler)
				throws IOException {
			if ("file".equals(uri.getScheme())) {
				return reader.read(Path.of(uri));
			}

			var path = getCachePath(uri);
			if (Files.isRegularFile(path)) {
				var lastModifiedTime = Files.getLastModifiedTime(path);
				var now = System.currentTimeMillis();
				var age = now - lastModifiedTime.toMillis();
				var ageInHours = age / 1000 / 60 / 60;
				if (ageInHours < 8) {
					return reader.read(path);
				}
			}

			try {
				var content = basicGetContent(uri, bodyHandler);
				Files.createDirectories(path.getParent());
				writer.write(path, content);
				return content;
			} catch (InterruptedException e) {
				throw new IOException(e);
			}
		}

		public Document getXMLContent(URI uri) throws IOException {
			var content = getContent(uri);
			try {
				var builder = newDocumentBuilder();
				return builder.parse(new InputSource(new StringReader(content)));
			} catch (ParserConfigurationException | SAXException e) {
				throw new IOException(uri + " : " + e.getMessage(), e);
			}
		}
	}

	public static final class ArgumentUtil {
		private ArgumentUtil() {
		}

		public static List<String> getArguments(IApplicationContext context) {
			return new ArrayList<>(Arrays.asList((String[]) context.getArguments().get("application.args")));
		}

		public static boolean getArgument(String name, List<String> args) {
			return args.remove(name);
		}

		public static String getArgument(String name, List<String> args, String defaultValue) {
			var index = args.indexOf(name);
			if (index == -1) {
				return defaultValue;
			}
			args.remove(index);
			if (index >= args.size()) {
				throw new IllegalArgumentException("An argument value is expected after " + name);
			}
			return args.remove(index);
		}

		public static List<String> getArguments(String name, List<String> args, List<String> defaultValue) {
			var index = args.indexOf(name);
			if (index == -1) {
				return defaultValue;
			}
			args.remove(index);
			if (index >= args.size()) {
				throw new IllegalArgumentException("An argument value is expected after " + name);
			}

			var result = new ArrayList<String>();
			while (index < args.size() && !args.get(index).startsWith("-")) {
				result.add(args.remove(index));
			}
			return result;
		}
	}

	public static final class BOMUtil {
		public BOMUtil() {
		}

		public static BomXmlGenerator createBomXMLGenerator(Version version, Bom bom) {
			var thread = Thread.currentThread();
			var contextClassLoader = thread.getContextClassLoader();
			var propertyName = XMLOutputFactory.class.getName();
			var property = System.getProperty(propertyName);
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

		public static Property createProperty(String name, String value) {
			var property = new Property();
			property.setName(name);
			property.setValue(value);
			return property;
		}

		public static void addAnnotation(Bom bom, String name, Stream<? extends CharSequence> values) {
			var annotations = bom.getAnnotations();
			if (annotations == null) {
				annotations = new ArrayList<Annotation>();
			}
			annotations.add(createAnnotation(name, values));
			bom.setAnnotations(annotations);
		}

		public static Annotation createAnnotation(String name, Stream<? extends CharSequence> values) {
			var annotation = new Annotation();
			annotation.setText(name + "=" + values.collect(INDENTED_PROPERTY_VALUE_COLLECTOR));
			return annotation;
		}

		public static Property createProperty(String name, Stream<? extends CharSequence> values) {
			var property = new Property();
			property.setName(name);
			property.setValue(values.collect(INDENTED_PROPERTY_VALUE_COLLECTOR));
			return property;
		}

		public static void addExternalReference(Component component, ExternalReference.Type type, String url) {
			var externalReference = createExternalReference(type, url);
			var externalReferences = component.getExternalReferences();
			if (externalReferences == null || !externalReferences.contains(externalReference)) {
				component.addExternalReference(externalReference);
			}
		}

		public static ExternalReference createExternalReference(ExternalReference.Type type, String url) {
			var externalReference = new ExternalReference();
			externalReference.setType(type);
			externalReference.setUrl(url);
			return externalReference;
		}

		public static String computeHash(String algorithm, byte[] bytes) {
			try {
				var digest = MessageDigest.getInstance(algorithm);
				var result = digest.digest(bytes);
				return HexFormat.of().formatHex(result);
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException(e);
			}
		}

		public static String urlEncodeQueryParameter(String value) {
			// Decode characters such as / and: that are very common in URIs
			// and do not need to be encoded within a URI's query string.
			var result = URLEncoder.encode(value, StandardCharsets.UTF_8);
			return result.replace("%2F", "/").replace("%3A", ":");
		}
	}
}
