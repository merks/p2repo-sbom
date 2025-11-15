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

import static org.eclipse.cbi.p2repo.sbom.ArgumentUtil.getArgument;
import static org.eclipse.cbi.p2repo.sbom.ArgumentUtil.getArguments;
import static org.eclipse.cbi.p2repo.sbom.URIUtil.parseRedirections;
import static org.eclipse.cbi.p2repo.sbom.URIUtil.toURI;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.NullProgressMonitor;
import org.eclipse.core.runtime.SubMonitor;
import org.eclipse.equinox.app.IApplication;
import org.eclipse.equinox.app.IApplicationContext;

public class SBOMApplication implements IApplication {

	private static final Pattern ARCHIVE_PATTERN = Pattern.compile("archive:(.*)!/.*");

	private static final URI SBOM_RENDERER_URI = URI.create("https://download.eclipse.org/cbi/sbom");

	@Override
	public Object start(IApplicationContext context) throws Exception {
		generate(getArguments(context), new NullProgressMonitor());
		return EXIT_OK;
	}

	public static void generate(List<String> arguments, IProgressMonitor monitor) throws Exception {
		var args = new ArrayList<>(arguments);
		var sbomGeneratorResults = new ArrayList<SBOMGenerator.Result>();
		var installationsFolder = getArgument("-installations", args, null);
		var verbose = getArgument("-verbose", args);
		var byteCache = args.contains("-strict-p2-source-repositories")
				? Files.createTempDirectory("org.eclipse.cbi.p2repo.sbom.byte-cache")
				: null;
		if (byteCache != null) {
			byteCache.toFile().deleteOnExit();
		}

		if (installationsFolder != null) {
			var installationPattern = Pattern
					.compile(getArgument("-installation-pattern", args, ".*\\.(zip|tar|tar.gz)$"));
			var xmlOutputsFolder = getArgument("-xml-outputs", args, null);
			var jsonOutputsFolder = getArgument("-json-outputs", args, null);
			try (var contents = Files.newDirectoryStream(Path.of(installationsFolder).toAbsolutePath(),
					path -> installationPattern.matcher(path.getFileName().toString()).matches())) {
				var paths = StreamSupport.stream(contents.spliterator(), false).toList();
				var progress = SubMonitor.convert(monitor, paths.size());
				for (Path path : paths) {
					var effectiveArgs = new ArrayList<>(args);
					if (verbose) {
						effectiveArgs.add(0, "-verbose");
					}
					effectiveArgs.add("-installation");
					effectiveArgs.add(path.toString());
					if (xmlOutputsFolder != null) {
						effectiveArgs.add("-xml-output");
						effectiveArgs.add(xmlOutputsFolder + "/"
								+ path.getFileName().toString().replaceAll("\\.(zip|tar|tar.gz)$", "-sbom.xml"));
					}
					if (jsonOutputsFolder != null) {
						effectiveArgs.add("-json-output");
						effectiveArgs.add(jsonOutputsFolder + "/"
								+ path.getFileName().toString().replaceAll("\\.(zip|tar|tar.gz)$", "-sbom.json"));
					}
					if (byteCache != null) {
						effectiveArgs.add("-byte-cache");
						effectiveArgs.add(byteCache.toString());
					}
					sbomGeneratorResults.add(
							new SBOMGenerator(effectiveArgs).generate(progress.split(1, SubMonitor.SUPPRESS_NONE)));
				}
			}
		} else {
			var effectiveArgs = new ArrayList<>(args);
			if (verbose) {
				effectiveArgs.add(0, "-verbose");
			}
			sbomGeneratorResults.add(new SBOMGenerator(effectiveArgs).generate(monitor));
		}

		var index = getArgument("-index", args, null);
		if (index != null) {
			var indexPath = Path.of(index).toAbsolutePath();
			if (verbose) {
				System.out.println("Generating Index: " + index);
			}
			var render = getArgument("-renderer", args, SBOM_RENDERER_URI.toString());
			generateIndex(indexPath, arguments, URI.create(render), sbomGeneratorResults);

			var previewRedirections = parseRedirections(getArguments("-preview", args, List.of()));
			var redirectedIndex = previewRedirections.redirect(toURI(indexPath));
			if (!"file".equals(redirectedIndex.getScheme())) {
				URIUtil.openURL(redirectedIndex);
			}
		}
	}

	private static void generateIndex(Path indexPath, List<String> arguments, URI renderer,
			List<SBOMGenerator.Result> sbomGeneratorResults) throws IOException {
		var html = """
				<!DOCTYPE html>
				<html lang=en>
				<head>
					<title>SBOM Index</title>
					<link rel="icon" type="image/ico" href="https://download.eclipse.org/cbi/sbom/favicon.ico">
						<style>
							img {
								max-height: 3ex;
							}
							td {
								vertical-align: top;
							}

						</style>
				</head>
				<body>
					<table>
						${items}
					</table>

					<details>
						<summary>Arguments</summary>
						<pre>${args}</pre>
					</details>

					<script>
						// This allows the arguments to the file query parameter to be relative such that the folder with the index.html and the SBOMs is portable.
						for (const a of document.querySelectorAll('a')) {
							const href = a.href;
							const match = /(?<renderer>.*\\?file=)(?<file>.*)/.exec(href);
							if (match) {
								const renderer = match.groups.renderer;
								const file = match.groups.file;
								const resolvedURL = new URL(file, location);
								a.href = `${renderer}${resolvedURL}`;
							}
						}
					</script>
				</body>
				</html>
				""";

		html = html.replace("${title}", "SBOM Index");
		html = html.replace("${args}", toString(arguments));

		var items = new ArrayList<String>();
		for (var sbomGenerator : sbomGeneratorResults) {
			var content = new ArrayList<String>();
			content.add("""
					<td>
						<details>
							<summary></summary>
							<pre style="font-size: 85%">${args}</pre>
						</details>
					</td>
					""".replace("${args}", toString(sbomGenerator.arguments())));

			var inputs = sbomGenerator.inputs();
			var inputLinks = inputs.stream().map(SBOMApplication::toLink)
					.collect(Collectors.joining("<br/>", "<td>", "</td>"));
			content.add(inputLinks);

			var outputs = sbomGenerator.outputs();
			for (var output : outputs) {
				var relativePath = indexPath.getParent().relativize(output).toString();
				var label = relativePath.endsWith(".json") ? "json" : "xml";
				var hrefs = """
						<td>
							<a href="${renderer}/?file=${file}"><img src="https://img.shields.io/static/v1?logo=eclipseide&label=Rendered&message=${label}&style=for-the-badge&logoColor=gray&labelColor=rgb(255,164,44)&color=gray"/></a>
						</td>
						<td>
							<a href="${file}"><img src="https://img.shields.io/static/v1?logo=eclipseide&label=Raw&message=${label}&style=for-the-badge&logoColor=gray&labelColor=rgb(255,164,44)&color=gray"/></a>
						</td>
						""";
				hrefs = hrefs //
						.replace("${renderer}", renderer.toString()) //
						.replace("${file}", relativePath) //
						.replace("${label}", label);
				content.add(hrefs);
			}

			var item = """
					<tr>
						${content}
					</tr>
					""";
			items.add(item.replace("${content}", String.join("\n", content).replace("\n", "\n	")));
		}

		var formattedItems = String.join("\n", items).replace("\n", "\n		");
		html = html.replace("${items}", formattedItems);
		Files.writeString(indexPath, html);
	}

	private static String toString(List<String> arguments) {
		return arguments.stream().map(it -> !it.startsWith("-") ? "  " + it : it).collect(Collectors.joining("&#10;"));
	}

	private static String toLink(URI uri) {
		var value = uri.toString();
		var archiveMatcher = ARCHIVE_PATTERN.matcher(value);
		var baseURI = archiveMatcher.matches() ? archiveMatcher.group(1) : value;
		return "<a href='" + baseURI + "'>" + baseURI + "</a>";
	}

	@Override
	public void stop() {
	}
}