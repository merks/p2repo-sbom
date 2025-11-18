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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.eclipse.core.resources.IContainer;
import org.eclipse.core.resources.IFile;
import org.eclipse.core.resources.IResource;
import org.eclipse.core.resources.ResourcesPlugin;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.core.runtime.IPath;
import org.eclipse.jface.dialogs.IDialogSettings;
import org.eclipse.jface.resource.ResourceLocator;
import org.eclipse.jface.viewers.IStructuredSelection;
import org.eclipse.jface.widgets.WidgetFactory;
import org.eclipse.jface.window.Window;
import org.eclipse.jface.wizard.Wizard;
import org.eclipse.jface.wizard.WizardPage;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;
import org.eclipse.ui.INewWizard;
import org.eclipse.ui.IWorkbench;
import org.eclipse.ui.PlatformUI;
import org.eclipse.ui.dialogs.ContainerSelectionDialog;
import org.osgi.framework.FrameworkUtil;

public class NewSBOMWizard extends Wizard implements INewWizard {
	private IWorkbench workbench;

	private IContainer initialContainer;

	private Page page;

	public NewSBOMWizard() {
		setWindowTitle("New SBOM");
		setDialogSettings(
				PlatformUI.getDialogSettingsProvider(FrameworkUtil.getBundle(NewSBOMWizard.class)).getDialogSettings());
	}

	@Override
	public void init(IWorkbench workbench, IStructuredSelection selection) {
		this.workbench = workbench;
		if (selection.getFirstElement() instanceof IContainer container) {
			initialContainer = container;
		}
	}

	@Override
	public boolean performFinish() {
		return page.performFinish(workbench);
	}

	@Override
	public void addPages() {
		page = new Page(initialContainer);
		addPage(page);
	}

	private static class Page extends WizardPage {
		private static final List<Map.Entry<String, String>> TEMPLATES = List.of( //
				Map.entry("SBOM of p2 Repository", """
						-central-search
						-advisory
						-process-bundle-classpath
						-input
						https://download.eclipse.org/jdtls/milestones/1.51.0/repository
						"""), //
				Map.entry("SBOM of Local Installation", """
						-central-search
						-advisory
						-process-bundle-classpath
						-installation
						${installation}
						"""), //
				Map.entry("SBOM of Remote Installation", """
						-central-search
						-advisory
						-process-bundle-classpath
						-installation
						https://download.eclipse.org/oomph/products/eclipse-inst-linux64.tar.gz
						"""));

		private final List<Map.Entry<String, String>> templates = new ArrayList<>(TEMPLATES);

		private final IContainer initialContainer;

		private Text locationText;

		private Text argumentsText;

		private Button showInRenderer;

		public Page(IContainer initialContainer) {
			super("page");
			this.initialContainer = initialContainer;
			setTitle("Generate SBOM");
			setDescription("Generate an SBOM according to the specified details");
			setImageDescriptor(ResourceLocator.imageDescriptorFromBundle(getClass(), "icons/newsbom_wiz.svg").get());
		}

		@Override
		public void createControl(Composite parent) {
			var composite = WidgetFactory.composite(SWT.NONE) //
					.layout(new GridLayout(3, false)) //
					.font(parent.getFont()) //
					.create(parent);

			WidgetFactory.label(SWT.NONE) //
					.text("Folder:").tooltip("The workspace folder into which to generate the results")
					.layoutData(new GridData(SWT.BEGINNING, SWT.CENTER, false, false)) //
					.create(composite);

			locationText = WidgetFactory.text(SWT.BORDER)
					.text(initialContainer == null ? "" : initialContainer.getFullPath().toString())
					.message("The workspace foldekjr into which to generate the results")
					.layoutData(new GridData(SWT.FILL, SWT.CENTER, true, false))//
					.onModify(e -> {
						validate();
					}) //
					.create(composite);
			locationText.selectAll();

			WidgetFactory.button(SWT.PUSH) //
					.text("Browse...").layoutData(new GridData(SWT.BEGINNING, SWT.CENTER, false, false)) //
					.onSelect(e -> {
						var dialog = new ContainerSelectionDialog(getShell(), getLocation(), true, "Message");
						dialog.setMessage("Bar");
						if (dialog.open() == Window.OK) {
							var result = dialog.getResult();
							if (result.length == 1 && result[0] instanceof IPath path) {
								locationText.setText(path.toString());
								locationText.selectAll();
							}
						}
					}) //
					.create(composite);

			WidgetFactory.label(SWT.NONE) //
					.text("Template:") //
					.tooltip("A template choice to fill out the arguments below")
					.layoutData(new GridData(SWT.BEGINNING, SWT.CENTER, false, false)).create(composite);

			var args = getArgumentsDialogSettings().get("args");
			if (args != null) {
				templates.add(0, Map.entry("SBOM - Previously Used", String.join("\n", args.split(" "))));
			}

			var templateChoice = new Combo(composite, SWT.READ_ONLY | SWT.DROP_DOWN | SWT.SIMPLE);
			templateChoice.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 2, 1));
			templateChoice.setItems(templates.stream().map(Map.Entry::getKey).toArray(String[]::new));
			templateChoice.addModifyListener(e -> setTemplateChoice(templateChoice.getText()));

			argumentsText = WidgetFactory.text(SWT.BORDER | SWT.MULTI | SWT.H_SCROLL | SWT.V_SCROLL) // s
					.layoutData(new GridData(SWT.FILL, SWT.FILL, true, true, 3, 1)).create(composite);

			showInRenderer = WidgetFactory.button(SWT.CHECK) //
					.text("Open in renderer") //
					.layoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 3, 1)) //
					.create(composite);
			showInRenderer.setSelection(true);

			templateChoice.setText(templates.get(0).getKey());

			validate();

			setControl(composite);
		}

		public boolean performFinish(IWorkbench workbench) {
			var container = getLocation();
			var location = container.getLocation();
			var render = showInRenderer.getSelection();
			var args = new ArrayList<>(List.of(argumentsText.getText().split("\\s+")));
			getArgumentsDialogSettings().put("args", String.join(" ", args));
			args.add("-xml-output");
			args.add(location.append("sbom.xml").toOSString());
			args.add("-json-output");
			args.add(location.append("sbom.json").toOSString());
			args.add("-index");
			args.add(location.append("index.html").toOSString());
			var renderURL = SBOMRenderer.getRender();
			if (renderURL != null) {
				args.add("-renderer");
				args.add(renderURL);
			}
			getControl().getDisplay().asyncExec(() -> {
				var generateDialog = new GenerateDialog(workbench.getModalDialogShellProvider().getShell(), args,
						container.getFile(IPath.fromOSString("index.html")), render);
				generateDialog.setBlockOnOpen(false);
				generateDialog.open();
			});
			return true;
		}

		private void validate() {
			var location = getLocation();
			var project = location == null ? null : location.getProject();
			var complete = project != null && project.isAccessible();
			setErrorMessage(complete ? null : "Specify a folder in an accessible project");
			setPageComplete(complete);
		}

		private IContainer getLocation() {
			var path = IPath.fromOSString(locationText.getText());
			var root = ResourcesPlugin.getWorkspace().getRoot();
			if (path.segmentCount() == 1) {
				return root.getProject(path.toString());
			}
			if (path.segmentCount() >= 1) {
				return root.getFolder(path);
			}
			return root;
		}

		private void setTemplateChoice(String text) {
			var value = templates.stream().filter(it -> text.equals(it.getKey())).findFirst().get().getValue();
			argumentsText.setText(value.replace("${installation}", SBOMUIUtil.getEclipseInstallLocation()));
		}

		private IDialogSettings getArgumentsDialogSettings() {
			var dialogSettings = getDialogSettings();
			var section = dialogSettings.getSection("arguments");
			return section == null ? dialogSettings.addNewSection("arguments") : section;
		}
	}

	private static class GenerateDialog extends DialogWithProgress {

		private final List<String> args;

		private final boolean showInRenderer;

		private final IFile file;

		public GenerateDialog(Shell parentShell, List<String> args, IFile file, boolean showInRenderer) {
			super(parentShell);
			this.args = args;
			this.file = file;
			this.showInRenderer = showInRenderer;
		}

		@Override
		public int open() {
			var result = super.open();
			buttonPressed(OK);
			return result;
		}

		@Override
		protected void setEnabled(Control control, boolean enabled) {
			if (control instanceof Text) {
				return;
			}
			super.setEnabled(control, enabled);
		}

		@Override
		protected Control createDialogArea(Composite parent) {
			var container = (Composite) super.createDialogArea(parent);
			var layout = new GridLayout(1, false);
			container.setLayout(layout);

			var text = WidgetFactory.text(SWT.BORDER | SWT.H_SCROLL | SWT.V_SCROLL | SWT.READ_ONLY)
					.layoutData(new GridData(SWT.FILL, SWT.FILL, true, true, 1, 1)).create(container);
			text.setText(String.join("\n", args));

			createProgressMonitorPart(container, new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
			return container;
		}

		@Override
		protected boolean generate() {
			var result = generate(args, false);
			try {
				file.getParent().refreshLocal(IResource.DEPTH_INFINITE, null);
			} catch (CoreException e) {
			}
			if (result && showInRenderer) {
				SBOMRenderer.open(file);
			}
			return result;
		}
	}

}
