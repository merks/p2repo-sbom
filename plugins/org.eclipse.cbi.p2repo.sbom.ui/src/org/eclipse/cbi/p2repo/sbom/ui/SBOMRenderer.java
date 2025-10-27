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
package org.eclipse.cbi.p2repo.sbom.ui;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

import org.eclipse.core.runtime.IPath;
import org.eclipse.oomph.internal.util.HTTPServer;
import org.eclipse.oomph.internal.util.HTTPServer.FileContext;
import org.eclipse.ui.PlatformUI;
import org.eclipse.ui.browser.IWorkbenchBrowserSupport;
import org.json.JSONArray;
import org.json.JSONObject;

public final class SBOMRenderer {

	private SBOMRenderer() {
		throw new UnsupportedOperationException("Do not instantiate");
	}

	private static HTTPServer httpServer;

	public static void show(Path path) {
		var display = PlatformUI.getWorkbench().getDisplay();
		display.asyncExec(() -> {
			try {
				var httpServer = getHTTPServer();
				var url = "http://localhost:" + httpServer.getPort();
				httpServer.addContext(
						new FileContext("/" + path.getParent().getFileName(), true, path.getParent().toFile()));

				var browserSupport = PlatformUI.getWorkbench().getBrowserSupport();
				var browser = browserSupport.createBrowser(IWorkbenchBrowserSupport.AS_EDITOR, "sbom", "SBOM",
						"The SBOM for the product.");
				var rendererURL = url + "/sbom/index.html?file=" + url + "/" + path.getParent().getFileName() + "/"
						+ path.getFileName();
				browser.openURL(new URL(rendererURL));
			} catch (Exception e) {
				SBOMUIUtil.openErrorDialog(e);
			}
		});
	}

	private static HTTPServer getHTTPServer() throws IOException, InterruptedException {
		if (httpServer == null) {
			httpServer = new HTTPServer(8084, 9000);
			var www = intializeRenderer();
			httpServer.addContext(new FileContext("/sbom", true, www.toFile()));
		}
		return httpServer;

	}

	private static IPath intializeRenderer() throws IOException, InterruptedException {
		var stateLocation = SBOMUIUtil.getStateLocation();
		var httpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();
		var www = stateLocation.append("www");
		Files.createDirectories(www.toPath());

		var body = httpClient.send(
				HttpRequest.newBuilder(URI.create("https://api.github.com/repos/eclipse-cbi/p2repo-sbom/contents/www"))
						.GET().build(),
				BodyHandlers.ofString()).body();
		@SuppressWarnings("unchecked")
		var wwwContents = (Iterable<JSONObject>) (Iterable<?>) new JSONArray(body);
		for (JSONObject resource : wwwContents) {
			var name = resource.getString("name");
			var targetResource = www.append(name);
			try (var content = httpClient
					.send(HttpRequest.newBuilder(URI.create(resource.getString("download_url"))).GET().build(),
							BodyHandlers.ofInputStream())
					.body()) {
				Files.copy(content, targetResource.toPath(), StandardCopyOption.REPLACE_EXISTING);
			}
		}
		return www;
	}
}
