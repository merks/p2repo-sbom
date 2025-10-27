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
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public final class URIUtil {

	private URIUtil() {
		throw new UnsupportedOperationException("Do not instantiate");
	}

	public static void openURL(URI uri) throws IOException {
		Desktop.getDesktop().browse(uri);
	}

	public static URI toURI(String value) {
		return value.startsWith("https://") | value.startsWith("http://") ? URI.create(value)
				: toURI(Path.of(value).toAbsolutePath());
	}

	public static URI toURI(Path path) {
		return toURI(path.toUri());
	}

	public static URI toURI(URI uri) {
		return URI.create(uri.toString().replaceAll("file:///", "file:/").replaceAll("/$", "")).normalize();
	}

	public static URI getRedirectedURI(URI location, Map<URI, URI> uriRedirections) {
		for (var entry : uriRedirections.entrySet()) {
			var relativizedURI = entry.getKey().relativize(location);
			if (relativizedURI.getScheme() == null) {
				return getRedirectedURI(URI.create(entry.getValue().toString() + relativizedURI), uriRedirections);
			}
		}
		return location;
	}

	public static Map<URI, URI> parseRedirections(List<String> redirections) {
		var uriRedirections = new TreeMap<URI, URI>((o1, o2) -> {
			// Longest URI first for redirection.
			var result = Integer.compare(o2.toString().length(), o1.toString().length());
			return result == 0 ? o1.compareTo(o2) : result;
		});

		for (var uriRedirection : redirections) {
			var pair = uriRedirection.split("->");
			if (pair.length != 2) {
				throw new IllegalArgumentException("Expected a '->' in the redirection:" + uriRedirection);
			}
			uriRedirections.put(toURI(pair[0]), toURI(pair[1]));
		}

		return uriRedirections;
	}
}