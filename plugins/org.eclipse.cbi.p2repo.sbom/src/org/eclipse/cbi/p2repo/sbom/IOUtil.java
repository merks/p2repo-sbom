/**
 * Copyright (c) 2025 Eclipse contributors and others.
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
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;
import java.util.zip.ZipInputStream;

import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;

public final class IOUtil {
	private static final Pattern SUPPORTED_ARCHIVE_PATTERN = Pattern
			.compile("(?<name>.*)\\.(?<extension>zip|tar|tar.gz)$");

	private IOUtil() {
		throw new UnsupportedOperationException("Do not instantiate");
	}

	public static Map<String, byte[]> getZipContents(byte[] bytes) throws IOException {
		var entries = new TreeMap<String, byte[]>();
		try (var zip = new ZipInputStream(new ByteArrayInputStream(bytes))) {
			for (var entry = zip.getNextEntry(); entry != null; entry = zip.getNextEntry()) {
				if (!entry.isDirectory()) {
					var name = entry.getName();
					entries.put(name, zip.readAllBytes());
				}
			}
			return entries;
		}
	}

	public static Path extractInstallation(Path archive) throws IOException {
		var fileName = archive.getFileName().toString();
		var matcher = SUPPORTED_ARCHIVE_PATTERN.matcher(fileName);
		if (!matcher.matches()) {
			throw new IllegalArgumentException("Unsupported archive format");
		}
		var baseName = matcher.group("name");
		var extension = matcher.group("extension");
		var target = archive.resolveSibling(baseName);
		if (!Files.isDirectory(target)) {
			Files.createDirectory(target);
			switch (extension) {
			case "zip": {
				try (var in = Files.newInputStream(archive)) {
					extractZip(in, target);
				}
				break;
			}
			case "tar": {
				try (var in = Files.newInputStream(archive)) {
					extractTar(in, target);
				}
				break;
			}
			case "tar.gz": {
				try (InputStream in = new GzipCompressorInputStream(Files.newInputStream(archive))) {
					extractTar(in, target);
				}
				break;
			}
			}
		}

		try (var targetContents = Files.newDirectoryStream(target, Files::isDirectory)) {
			var paths = new ArrayList<Path>();
			for (Path path : targetContents) {
				paths.add(path);
			}
			if (paths.isEmpty()) {
				throw new IllegalArgumentException("The folder " + target + "is empty");
			}
			return paths.size() == 1 ? paths.get(0) : target;
		}
	}

	private static void extractZip(InputStream in, Path target) throws IOException {
		try (var zip = new ZipInputStream(in)) {
			for (var entry = zip.getNextEntry(); entry != null; entry = zip.getNextEntry()) {
				var path = target.resolve(entry.getName());
				if (entry.isDirectory()) {
					Files.createDirectory(path);
				} else {
					Files.copy(zip, path);
				}
			}
		}
	}

	private static void extractTar(InputStream in, Path target) throws IOException {
		try (var tar = new TarArchiveInputStream(in)) {
			for (var entry = tar.getNextEntry(); entry != null; entry = tar.getNextEntry()) {
				var path = target.resolve(entry.getName());
				if (entry.isDirectory()) {
					Files.createDirectory(path);
				} else {
					Files.copy(tar, path);
				}
			}
		}
	}
}