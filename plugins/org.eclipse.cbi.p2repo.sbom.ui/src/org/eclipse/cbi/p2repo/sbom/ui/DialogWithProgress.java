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

import java.lang.reflect.InvocationTargetException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.cbi.p2repo.sbom.SBOMApplication;
import org.eclipse.core.runtime.OperationCanceledException;
import org.eclipse.core.runtime.ProgressMonitorWrapper;
import org.eclipse.jface.dialogs.Dialog;
import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.jface.operation.ModalContext;
import org.eclipse.jface.wizard.ProgressMonitorPart;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Shell;

/**
 * A dialog for configuring SBOM generation settings.
 */
public abstract class DialogWithProgress extends Dialog {

	private ProgressMonitorPart progressMonitorPart;

	public DialogWithProgress(Shell parentShell) {
		super(parentShell);
		setShellStyle(getShellStyle() & ~SWT.APPLICATION_MODAL | SWT.MIN);
	}

	@Override
	protected boolean isResizable() {
		return true;
	}

	@Override
	protected void configureShell(Shell newShell) {
		super.configureShell(newShell);
		newShell.setText("Generate SBOM");
	}

	protected abstract boolean generate();

	protected void createProgressMonitorPart(Composite container, GridData progressMonitorGridData) {
		var progressMonitorComposite = new Composite(container, SWT.BORDER);
		var progressMonitorLayout = new GridLayout();
		progressMonitorLayout.marginHeight = 0;
		progressMonitorLayout.marginWidth = 0;
		progressMonitorLayout.numColumns = 2;
		progressMonitorComposite.setLayout(progressMonitorLayout);

		progressMonitorGridData.exclude = true;
		progressMonitorComposite.setLayoutData(progressMonitorGridData);

		progressMonitorPart = new ProgressMonitorPart(progressMonitorComposite, new GridLayout(), true);
		progressMonitorPart.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
	}

	@Override
	protected void buttonPressed(int buttonId) {
		if (buttonId == IDialogConstants.OK_ID) {
			var progressMonitorPartComposite = progressMonitorPart.getParent();
			var progressMonitorPartCompositeGridData = (GridData) progressMonitorPartComposite.getLayoutData();
			progressMonitorPartCompositeGridData.exclude = false;
			progressMonitorPartComposite.getParent().layout(true);
			progressMonitorPart.attachToCancelComponent(null);

			// Only grow the dialog the first time, not after subsequence failures.
			//
			var shell = getShell();
			if (progressMonitorPartComposite.isVisible()) {
				var size = progressMonitorPartComposite.getSize();
				var shellSize = shell.getSize();
				shell.setSize(shellSize.x, shellSize.y + size.y + 11 / 10);
			} else {
				progressMonitorPartComposite.setVisible(true);
			}

			setEnabled(getContents(), false);

			Runnable handleFailure = () -> {
				progressMonitorPartCompositeGridData.exclude = true;
				progressMonitorPartComposite.setVisible(false);
				progressMonitorPartComposite.getParent().layout(true);
				setEnabled(getContents(), true);
			};

			if (!generate()) {
				handleFailure.run();
				return;
			}

			// This can be used to test the behavior of the progress part without
			// generating.
			//
			if (Boolean.FALSE) {
				var atomicInteger = new AtomicInteger(100);
				try {
					ModalContext.run(monitor -> {
						monitor.beginTask("Generating", 100);
						while (atomicInteger.decrementAndGet() > 0) {
							if (monitor.isCanceled()) {
								throw new OperationCanceledException();
							}
							monitor.worked(1);
							Thread.sleep(100);
						}
					}, true, progressMonitorPart, shell.getDisplay());
				} catch (InvocationTargetException | InterruptedException e) {
					handleFailure.run();
					return;
				}
			}
		}
		super.buttonPressed(buttonId);
	}

	@Override
	protected void handleShellCloseEvent() {
		if (getButton(CANCEL).isEnabled()) {
			super.handleShellCloseEvent();
		}
	}

	protected void setEnabled(Control control, boolean enabled) {
		if (control == progressMonitorPart) {
			return;
		}
		if (control instanceof Composite composite) {
			for (var child : composite.getChildren()) {
				setEnabled(child, enabled);
			}
		} else {
			control.setEnabled(enabled);
		}
	}

	protected boolean generate(List<String> arguments, boolean openInRenderer) {
		var args = new ArrayList<>(arguments);
		var cache = SBOMUIUtil.getStateLocation().append("cache");
		args.add("-cache");
		args.add(cache.toOSString());
		try {
			ModalContext.run(monitor -> {
				try {
					new SBOMApplication.Generator(args).generate(new ProgressMonitorWrapper(monitor) {
						@Override
						public void beginTask(String name, int totalWork) {
							checkCanceled();
							super.beginTask(name, totalWork);
						}

						@Override
						public void internalWorked(double work) {
							checkCanceled();
							super.internalWorked(work);
						}

						@Override
						public void setTaskName(String name) {
							checkCanceled();
							super.setTaskName(name);
						}

						@Override
						public void worked(int work) {
							checkCanceled();
							super.worked(work);
						}

						@Override
						public void subTask(String name) {
							checkCanceled();
							super.subTask(name);
						}

						private void checkCanceled() {
							if (isCanceled()) {
								throw new OperationCanceledException();
							}
						}
					});
				} catch (OperationCanceledException e) {
					throw new InterruptedException();
				} catch (Exception e) {
					throw new InvocationTargetException(e);
				}

				if (openInRenderer) {
					if (args.contains("-xml-output")) {
						SBOMRenderer.open(Path.of(args.get(args.indexOf("-xml-output") + 1)));
					}
					if (args.contains("-json-output")) {
						SBOMRenderer.open(Path.of(args.get(args.indexOf("-json-output") + 1)));
					}
				}
			}, true, progressMonitorPart, getShell().getDisplay());
			return true;
		} catch (InterruptedException e) {
			return false;
		} catch (InvocationTargetException e) {
			SBOMUIUtil.openErrorDialog(getParentShell(), e.getTargetException());
			return false;
		}
	}
}