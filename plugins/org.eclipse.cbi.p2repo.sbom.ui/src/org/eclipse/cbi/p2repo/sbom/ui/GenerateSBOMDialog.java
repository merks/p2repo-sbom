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

import static org.eclipse.core.runtime.URIUtil.toURI;

import java.lang.reflect.InvocationTargetException;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import org.eclipse.cbi.p2repo.sbom.SBOMApplication;
import org.eclipse.core.runtime.OperationCanceledException;
import org.eclipse.core.runtime.Platform;
import org.eclipse.core.runtime.ProgressMonitorWrapper;
import org.eclipse.jface.dialogs.Dialog;
import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.jface.operation.ModalContext;
import org.eclipse.jface.widgets.WidgetFactory;
import org.eclipse.jface.wizard.ProgressMonitorPart;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionListener;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.FileDialog;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;

/**
 * A dialog for configuring SBOM generation settings.
 */
public class GenerateSBOMDialog extends Dialog {

	private final List<Consumer<List<String>>> argumentHandlers = new ArrayList<>();

	private ProgressMonitorPart progressMonitorPart;

	private Button openRendererButton;

	public GenerateSBOMDialog(Shell parentShell) {
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

	@Override
	protected Control createDialogArea(Composite parent) {
		var container = (Composite) super.createDialogArea(parent);
		var layout = new GridLayout(3, false);
		container.setLayout(layout);

		createLabel(container, "Installation location:", "The Eclipse installation location of this installation");
		var installationLocationText = createText(container, SWT.BORDER | SWT.READ_ONLY, getEclipseInstallLocation());
		installationLocationText.setBackground(parent.getBackground());
		argumentHandlers.add(args -> {
			args.add("-installation");
			args.add(installationLocationText.getText());
		});
		new Label(container, SWT.NONE);

		createLabel(container, "XML output:", "Optional path for the XML SBOM output file");
		var xmlOutputText = createText(container, SWT.BORDER, getDefaultOutputPath(".xml"));
		createBrowseButton(container, xmlOutputText, "*.xml", "XML Files");
		argumentHandlers.add(args -> {
			var xmlOutput = xmlOutputText.getText();
			if (!xmlOutput.isBlank()) {
				args.add("-xml-output");
				args.add(xmlOutput);
			}
		});

		// JSON Output
		createLabel(container, "JSON output:", "Optional path for the JSON SBOM output file");
		var jsonOutputText = createText(container, SWT.BORDER, getDefaultOutputPath(".json"));
		createBrowseButton(container, jsonOutputText, "*.json", "JSON Files");
		argumentHandlers.add(args -> {
			var jsonOutput = jsonOutputText.getText();
			if (!jsonOutput.isBlank()) {
				args.add("-json-output");
				args.add(jsonOutput);
			}
		});

		var optionsLabel = new Label(container, SWT.NONE);
		optionsLabel.setText("Options:");
		var optionsLabelData = createFullWidthGridData();
		optionsLabelData.verticalIndent = 5;
		optionsLabel.setLayoutData(optionsLabelData);

		var clearlyDefinedButton = createCheckButton(container, "Query ClearlyDefined",
				"Query ClearlyDefined for license information");
		argumentHandlers.add(args -> {
			if (clearlyDefinedButton.getSelection()) {
				args.add("-clearly-defined");
			}
		});

		var centralSearch = createCheckButton(container, "Search Maven Central",
				"Query Maven Central for additional artifact information");
		argumentHandlers.add(args -> {
			if (centralSearch.getSelection()) {
				args.add("-central-search");
			}
		});

		var fetchAdvisories = createCheckButton(container, "Fetch advisories", "Query OSV for security advisories");
		argumentHandlers.add(args -> {
			if (fetchAdvisories.getSelection()) {
				args.add("-advisory");
			}
		});

		var processBundleClasspath = createCheckButton(container, "Process Bundle-ClassPath",
				"Process nested JARs from Bundle-ClassPath manifest entries");
		argumentHandlers.add(args -> {
			if (processBundleClasspath.getSelection()) {
				args.add("-process-bundle-classpath");
			}
		});

		var progressMonitorComposite = new Composite(container, SWT.BORDER);
		var progressMonitorLayout = new GridLayout();
		progressMonitorLayout.marginHeight = 0;
		progressMonitorLayout.marginWidth = 0;
		progressMonitorLayout.numColumns = 2;
		progressMonitorComposite.setLayout(progressMonitorLayout);
		var progressMonitorGridData = createFullWidthGridData();
		progressMonitorGridData.exclude = true;
		progressMonitorComposite.setLayoutData(progressMonitorGridData);

		progressMonitorPart = new ProgressMonitorPart(progressMonitorComposite, new GridLayout(), true);
		progressMonitorPart.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));

		return container;
	}

	@Override
	protected Control createButtonBar(Composite parent) {
		var composite = WidgetFactory.composite(SWT.NONE).layout(new GridLayout(2, false))
				.layoutData(new GridData(GridData.HORIZONTAL_ALIGN_END | GridData.VERTICAL_ALIGN_CENTER))
				.font(parent.getFont()).create(parent);
		openRendererButton = new Button(composite, SWT.CHECK);
		openRendererButton.setText("Open in renderer");
		openRendererButton.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
		return super.createButtonBar(composite);
	}

	@Override
	protected void createButtonsForButtonBar(Composite parent) {
		createButton(parent, IDialogConstants.OK_ID, "Generate", true);
		createButton(parent, IDialogConstants.CANCEL_ID, IDialogConstants.CANCEL_LABEL, false);
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
				shell.setSize(shellSize.x, shellSize.y + size.y);
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

	private void setEnabled(Control control, boolean enabled) {
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

	private Label createLabel(Composite container, String text, String toolTipText) {
		var result = new Label(container, SWT.NONE);
		result.setText(text);
		result.setToolTipText(toolTipText);
		return result;
	}

	private Text createText(Composite container, int style, String text) {
		var result = new Text(container, style);
		result.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
		result.setText(text);
		return result;
	}

	private Button createBrowseButton(Composite container, Text text, String filterExtension, String filterName) {
		var result = new Button(container, SWT.PUSH);
		result.setText("Browse...");
		result.addSelectionListener(SelectionListener.widgetSelectedAdapter(e -> {
			var dialog = new FileDialog(getShell(), SWT.SAVE);
			dialog.setFilterExtensions(new String[] { filterExtension, "*.*" });
			dialog.setFilterNames(new String[] { filterName, "All Files" });
			try {
				var path = Path.of(text.getText());
				dialog.setFileName(path.getFileName().toString());
				dialog.setFilterPath(path.getParent().toString());
			} catch (Exception ex) {
				//$FALL-THROUGH$
			}
			var file = dialog.open();
			if (file != null) {
				text.setText(file);
			}
		}));
		return result;
	}

	private Button createCheckButton(Composite container, String text, String tooltipText) {
		var result = new Button(container, SWT.CHECK);
		result.setText(text);
		result.setToolTipText(tooltipText);
		result.setLayoutData(createFullWidthGridData());
		return result;
	}

	private GridData createFullWidthGridData() {
		return new GridData(SWT.FILL, SWT.CENTER, true, false, 3, 1);
	}

	private String getEclipseInstallLocation() {
		var explicitInstallationLocation = System.getProperty("org.eclipse.cbi.p2repo.sbom.installation.location");
		if (explicitInstallationLocation != null) {
			return explicitInstallationLocation;
		}
		var url = Platform.getInstallLocation().getURL();
		try {
			var path = Path.of(toURI(url)).toRealPath();
			if (Platform.OS.isMac()) {
				if (path.toString().endsWith("/Contents/Eclipse")) {
					return path.getParent().getParent().toString();
				}
			}
			return path.toString();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private String getDefaultOutputPath(String extension) {
		var installLocation = getEclipseInstallLocation();
		if (installLocation == null || installLocation.isEmpty()) {
			return "";
		}
		try {
			var path = Path.of(installLocation);
			var fileName = path.getFileName().toString() + "-sbom" + extension;
			var parent = path.getParent();
			if (parent != null) {
				return parent.resolve(fileName).toString();
			}
			return fileName;
		} catch (InvalidPathException e) {
			return "";
		}
	}

	private boolean generate() {
		var args = new ArrayList<String>();
		for (var handler : argumentHandlers) {
			handler.accept(args);
		}

		var cache = SBOMUIUtil.getStateLocation().append("cache");
		args.add("-cache");
		args.add(cache.toOSString());

		var openInRenderer = openRendererButton.getSelection();

		try {
			ModalContext.run(monitor -> {
				try {
					SBOMApplication.generate(args, new ProgressMonitorWrapper(monitor) {
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
						SBOMRenderer.show(Path.of(args.get(args.indexOf("-xml-output") + 1)));
					} else if (args.contains("-json-output")) {
						SBOMRenderer.show(Path.of(args.get(args.indexOf("-json-output") + 1)));
					}
				}
			}, true, progressMonitorPart, getShell().getDisplay());
		} catch (InterruptedException e) {
			return false;
		} catch (InvocationTargetException e) {
			SBOMUIUtil.openErrorDialog(getParentShell(), e.getTargetException());
			return false;
		}
		return true;
	}
}