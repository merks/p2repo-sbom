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

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Arrays;

import org.eclipse.core.runtime.ILog;
import org.eclipse.core.runtime.IPath;
import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.MultiStatus;
import org.eclipse.core.runtime.Platform;
import org.eclipse.core.runtime.Status;
import org.eclipse.jface.dialogs.ErrorDialog;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.ui.PlatformUI;
import org.osgi.framework.FrameworkUtil;

public final class SBOMUIUtil {
	private SBOMUIUtil() {
		throw new UnsupportedOperationException("Do not instantiate");
	}

	public static IPath getStateLocation() {
		return Platform.getStateLocation(FrameworkUtil.getBundle(GenerateSBOMHandler.class));
	}

	public static ILog getLog() {
		return ILog.of(FrameworkUtil.getBundle(GenerateSBOMHandler.class));
	}

	public static void openErrorDialog(Throwable throwable) {
		openErrorDialog(PlatformUI.getWorkbench().getModalDialogShellProvider().getShell(), throwable);
	}

	public static void openErrorDialog(Shell shell, Throwable throwable) {
		var stackTrace = new StringWriter();
		throwable.printStackTrace(new PrintWriter(stackTrace));
		var parts = Arrays.asList(stackTrace.toString().split("\r?\n")).stream()
				.map(line -> new Status(IStatus.ERROR, SBOMUIUtil.class, line.replace("\t", "    "))).toList();
		var status = new MultiStatus(SBOMUIUtil.class, 0, parts.toArray(IStatus[]::new), stackTrace.toString(), null);
		new ErrorDialog(shell, "Generator Failure", "An exception was thrown during generation", status,
				IStatus.ERROR) {
			@Override
			protected void constrainShellSize() {
				var shell = getShell();
				var size = shell.getSize();
				var computeSize = shell.computeSize(size.x * 11 / 10, size.y * 11 / 10);
				var computeTrim = shell.computeTrim(0, 0, computeSize.x, computeSize.y);
				shell.setSize(computeTrim.width, size.y);
				super.constrainShellSize();
			}

			@Override
			protected boolean shouldShowDetailsButton() {
				return true;
			}
		}.open();

	}
}
