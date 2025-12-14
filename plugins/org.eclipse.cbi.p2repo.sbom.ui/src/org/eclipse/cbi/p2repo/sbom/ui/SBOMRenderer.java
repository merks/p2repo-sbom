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

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.regex.Pattern;

import org.eclipse.cbi.p2repo.sbom.IOUtil;
import org.eclipse.core.resources.IFile;
import org.eclipse.core.resources.IProject;
import org.eclipse.core.resources.ResourcesPlugin;
import org.eclipse.core.runtime.IPath;
import org.eclipse.jface.resource.ResourceLocator;
import org.eclipse.oomph.internal.util.HTTPServer;
import org.eclipse.oomph.internal.util.HTTPServer.FileContext;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.ui.IEditorInput;
import org.eclipse.ui.IEditorSite;
import org.eclipse.ui.IFileEditorInput;
import org.eclipse.ui.IWorkbench;
import org.eclipse.ui.PartInitException;
import org.eclipse.ui.PlatformUI;
import org.eclipse.ui.browser.IWorkbenchBrowserSupport;
import org.eclipse.ui.internal.browser.WebBrowserEditor;
import org.eclipse.ui.internal.browser.WebBrowserEditorInput;
import org.eclipse.ui.part.FileEditorInput;
import org.json.JSONArray;
import org.json.JSONObject;

public class SBOMRenderer extends WebBrowserEditor {

	public static void open(IFile file) {
		LocalHostServer.open(file);
	}

	public static void open(Path path) {
		LocalHostServer.open(path);

	}

	public static String getRender() {
		return LocalHostServer.getRender();
	}

	private static final Pattern LOCALL_HOST_PATTERN = Pattern.compile("http://localhost:[0-9]+/(?<project>[^/]+).*");

	public SBOMRenderer() {
	}

	@Override
	public void createPartControl(Composite parent) {
		imageDescriptor = ResourceLocator.imageDescriptorFromBundle(getClass(), "icons/sbom.svg").get();
		super.createPartControl(parent);
	}

	@Override
	public void init(IEditorSite site, IEditorInput input) throws PartInitException {
		if (input instanceof IFileEditorInput fileEditorInput) {
			var file = fileEditorInput.getFile();
			try {
				var httpServer = LocalHostServer.addContext(file.getProject());
				var rendererURL = "http://localhost:" + httpServer.getPort() + file.getFullPath().toString();
				super.init(site,
						new WebBrowserEditorInput(URI.create(rendererURL).toURL(), IWorkbenchBrowserSupport.LOCATION_BAR
								| IWorkbenchBrowserSupport.NAVIGATION_BAR | IWorkbenchBrowserSupport.PERSISTENT));
				return;
			} catch (Exception e) {
				SBOMUIUtil.openErrorDialog(e);
			}
		} else if (input instanceof WebBrowserEditorInput webBrowserEditorInput) {
			var url = webBrowserEditorInput.getURL();
			if (url != null) {
				var matcher = LOCALL_HOST_PATTERN.matcher(url.toString());
				if (matcher.matches()) {
					try {
						var project = ResourcesPlugin.getWorkspace().getRoot().getProject(matcher.group("project"));
						if (project.isAccessible()) {
							LocalHostServer.addContext(project);
						} else {
							LocalHostServer.getHTTPServer();
						}
					} catch (IOException e) {
						SBOMUIUtil.openErrorDialog(e);
					}
				}
			}
		}
		super.init(site, input);
	}

	/**
	 * Avoid warnings in the plugin.xml.
	 */
	public static class ActionBarContributor
			extends org.eclipse.ui.internal.browser.WebBrowserEditorActionBarContributor {
	}

	private static final class LocalHostServer {

		private static HTTPServer httpServer;

		public static HTTPServer getHTTPServer() throws IOException {
			if (httpServer == null) {
				httpServer = new HTTPServer(8084, 9000);
				var www = intializeRenderer();
				httpServer.addContext(new FileContext("/sbom", true, true, www.toFile()));
			}
			return httpServer;
		}

		public static HTTPServer addContext(IProject project) throws IOException {
			var httpServer = LocalHostServer.getHTTPServer();
			httpServer.addContext(new FileContext("/" + project.getName(), true, new File(project.getLocationURI())));
			return httpServer;
		}

		public static void open(Path path) {
			var workbench = PlatformUI.getWorkbench();
			var display = workbench.getDisplay();
			display.asyncExec(() -> {
				try {
					var httpServer = getHTTPServer();
					var url = "http://localhost:" + httpServer.getPort();
					httpServer.addContext(
							new FileContext("/" + path.getParent().getFileName(), true, path.getParent().toFile()));
					var rendererURL = url + "/sbom/index.html?file=" + url + "/" + path.getParent().getFileName() + "/"
							+ path.getFileName();
					var input = new WebBrowserEditorInput(URI.create(rendererURL).toURL(),
							IWorkbenchBrowserSupport.LOCATION_BAR | IWorkbenchBrowserSupport.NAVIGATION_BAR);
					open(workbench, input);
				} catch (Exception e) {
					SBOMUIUtil.openErrorDialog(e);
				}
			});
		}

		public static void open(IFile file) {
			var workbench = PlatformUI.getWorkbench();
			var display = workbench.getDisplay();
			display.asyncExec(() -> {
				try {
					open(workbench, new FileEditorInput(file));
				} catch (Exception e) {
					SBOMUIUtil.openErrorDialog(e);
				}
			});
		}

		public static String getRender() {
			try {
				var httpServer = getHTTPServer();
				var url = "http://localhost:" + httpServer.getPort() + "/sbom";
				return url;
			} catch (Exception e) {
				SBOMUIUtil.openErrorDialog(e);
				return null;
			}
		}

		private static void open(IWorkbench workbench, IEditorInput input) throws PartInitException {
			workbench.getActiveWorkbenchWindow().getActivePage().openEditor(input,
					"org.eclipse.cbi.p2repo.sbom.ui.render");
		}

		private static IPath intializeRenderer() throws IOException {
			try {
				var stateLocation = SBOMUIUtil.getStateLocation();
				var httpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();
				var www = stateLocation.append("www");
				Files.createDirectories(www.toPath());

				var body = httpClient.send(HttpRequest
						.newBuilder(URI.create("https://api.github.com/repos/eclipse-cbi/p2repo-sbom/contents/www"))
						.GET().build(), BodyHandlers.ofString()).body();
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
			} catch (InterruptedException e) {
				throw IOUtil.toInterruptedIOException(e);
			}
		}
	}
}
