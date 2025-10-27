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
import java.util.Map;
import java.util.TreeMap;

import org.json.JSONObject;

public final class SPDXIndex {

	private final Map<String, String> spdxLicenceIds = new TreeMap<>();

	private final Map<String, String> spdxLicenceNames = new TreeMap<>();

	public SPDXIndex(ContentHandler contentHandler) {
		try {
			buildSPDXIndex(contentHandler);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private void buildSPDXIndex(ContentHandler contentHandler) throws IOException {
		buildSPDXIndex(contentHandler.getContent(URI.create("https://spdx.org/licenses/licenses.json")), "licenses");
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

	public boolean isValidID(String id) {
		return spdxLicenceIds.containsKey(id);
	}
}