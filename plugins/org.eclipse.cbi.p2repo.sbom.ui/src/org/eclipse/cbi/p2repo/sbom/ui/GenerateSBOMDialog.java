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

import static org.eclipse.cbi.p2repo.sbom.ui.SBOMUIUtil.getEclipseInstallLocation;

import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.jface.widgets.WidgetFactory;
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
public class GenerateSBOMDialog extends DialogWithProgress {

	private final List<Consumer<List<String>>> argumentHandlers = new ArrayList<>();

	private Button openRendererButton;

	public GenerateSBOMDialog(Shell parentShell) {
		super(parentShell);
	}

	@Override
	protected boolean generate() {
		var args = new ArrayList<String>();
		for (var handler : argumentHandlers) {
			handler.accept(args);
		}

		return generate(args, openRendererButton.getSelection());
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

		createProgressMonitorPart(container, createFullWidthGridData());

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
		openRendererButton.setSelection(true);
		return super.createButtonBar(composite);
	}

	@Override
	protected void createButtonsForButtonBar(Composite parent) {
		createButton(parent, IDialogConstants.OK_ID, "Generate", true);
		createButton(parent, IDialogConstants.CANCEL_ID, IDialogConstants.CANCEL_LABEL, false);
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
}