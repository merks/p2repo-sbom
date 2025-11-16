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

import java.awt.Desktop;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class URIUtil {

	private URIUtil() {
		throw new UnsupportedOperationException("Do not instantiate");
	}

	public static void openURL(URI uri) throws IOException {
		Desktop.getDesktop().browse(uri);
	}

	public static URI toURI(String value) {
		return value.startsWith("https://") || value.startsWith("http://") || value.startsWith("file:")
				? URI.create(value)
				: toURI(Path.of(value).toAbsolutePath());
	}

	public static URI toURI(Path path) {
		return toURI(path.toUri());
	}

	public static URI toURI(URI uri) {
		return URI.create(uri.toString().replaceAll("file:///", "file:/")).normalize();
	}

	public static URIMap parseRedirections(List<String> redirections) {
		var uriRedirections = new URIMap();
		for (var uriRedirection : redirections) {
			var pair = uriRedirection.split("->");
			if (pair.length != 2) {
				throw new IllegalArgumentException("Expected a '->' in the redirection:" + uriRedirection);
			}
			uriRedirections.put(toURI(pair[0]), toURI(pair[1]));
		}
		return uriRedirections;
	}

	public static final class URIMap {

		private final Map<URI, URI> map = new HashMap<>();

		private final List<List<PrefixMapping>> prefixMaps = new ArrayList<>();

		private URIMap() {
		}

		public URI redirect(URI uri) {
			var result = map.get(uri);
			if (result == null && !prefixMaps.isEmpty()) {
				var uriLiteral = uri.toString();
				for (var i = Math.min(prefixMaps.size() - 1, getSegementCount(uri.getRawPath())); i >= 0; --i) {
					var prefixes = prefixMaps.get(i);
					for (var j = prefixes.size() - 1; j >= 0; --j) {
						var entry = prefixes.get(j);
						var source = entry.source;
						if (uriLiteral.startsWith(source)) {
							return URI.create(entry.target + uriLiteral.substring(source.length()));
						}
					}
				}
			}
			return result == null ? uri : result;
		}

		public void put(URI sourceURI, URI targetURI) {
			var oldValue = map.put(sourceURI, targetURI);
			if (!targetURI.equals(oldValue)) {
				var sourcePath = sourceURI.getRawPath();
				var targetPath = targetURI.getRawPath();
				if (sourcePath != null && sourcePath.endsWith("/") && targetPath != null && targetPath.endsWith("/")) {
					var prefixMapping = new PrefixMapping(sourceURI, targetURI);
					var segementCount = getSegementCount(sourcePath);
					for (var i = prefixMaps.size(); i <= segementCount; ++i) {
						prefixMaps.add(new ArrayList<>());
					}
					var prefixes = prefixMaps.get(segementCount);
					prefixes.add(prefixMapping);
					if (oldValue != null) {
						prefixes.remove(new PrefixMapping(sourceURI, oldValue));
					}
				}
			}
		}

		private int getSegementCount(String path) {
			var count = 0;
			for (int i = path.indexOf('/', 1), length = path.length(); i >= 1
					&& i < length; i = path.indexOf('/', i + 1)) {
				++count;
			}
			return count;
		}

		@Override
		public String toString() {
			return map.toString();
		}

		private static record PrefixMapping(String source, String target) {
			PrefixMapping(URI source, URI target) {
				this(source.toString(), target.toString());
			}
		}
	}
}