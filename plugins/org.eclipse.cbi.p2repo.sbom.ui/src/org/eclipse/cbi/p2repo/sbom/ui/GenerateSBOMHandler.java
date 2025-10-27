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

import org.eclipse.core.commands.AbstractHandler;
import org.eclipse.core.commands.ExecutionEvent;
import org.eclipse.core.commands.ExecutionException;
import org.eclipse.ui.handlers.HandlerUtil;

public class GenerateSBOMHandler extends AbstractHandler {

	private static GenerateSBOMDialog generateSBOMDialog;

	@Override
	public Object execute(ExecutionEvent event) throws ExecutionException {
		if (generateSBOMDialog != null) {
			var shell = generateSBOMDialog.getShell();
			shell.setMinimized(false);
			shell.setFocus();
		} else {
			generateSBOMDialog = new GenerateSBOMDialog(HandlerUtil.getActiveWorkbenchWindow(event).getShell());
			generateSBOMDialog.open();
			generateSBOMDialog = null;
		}
		return null;
	}
}
