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

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class ByteCache {

	private final Path cache;

	public ByteCache(String cache) {
		this.cache = cache == null ? null : Path.of(cache).toAbsolutePath();
	}

	interface Reader {
		byte[] read(URI uri) throws IOException;
	}

	public byte[] getBytes(URI uri, Reader reader) throws IOException {
		if (cache == null) {
			return reader.read(uri);
		}

		var path = getCachePath(uri);
		if (Files.isRegularFile(path)) {
			return Files.readAllBytes(path);
		}

		Files.createDirectories(path.getParent());
		var bytes = reader.read(uri);
		Files.write(path, bytes);
		return bytes;
	}

	private Path getCachePath(URI uri) {
		var decodedURI = URLDecoder.decode(uri.toString(), StandardCharsets.UTF_8);
		var uriSegments = decodedURI.split("[:/?#&;]+");
		var result = cache.resolve(String.join("/", uriSegments));
		return result;
	}
}