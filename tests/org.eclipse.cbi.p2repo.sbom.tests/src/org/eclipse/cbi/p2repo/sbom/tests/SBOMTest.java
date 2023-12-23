/**
 * Copyright (c) 2023 Eclipse contributors and others.
 *
 * This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.eclipse.cbi.p2repo.sbom.tests;

import java.util.Arrays;

import org.cyclonedx.BomGeneratorFactory;
import org.cyclonedx.CycloneDxSchema;
import org.cyclonedx.generators.json.BomJsonGenerator;
import org.cyclonedx.generators.xml.BomXmlGenerator;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Hash;
import org.eclipse.cbi.p2repo.sbom.SBOMApplication;
import org.junit.jupiter.api.Test;

public class SBOMTest {

	@Test
	public void test() throws Exception {
		ExternalReference extRef = new ExternalReference();
		extRef.setType(ExternalReference.Type.BOM);
		extRef.setUrl("https://example.org/support/sbom/portal-server/1.0.0");
		extRef.setComment("An external SBOM that describes what this component includes");
		Hash md5 = new Hash(Hash.Algorithm.MD5, "2cd42512b65500dc7ba0ff13490b0b73");
		Hash sha1 = new Hash(Hash.Algorithm.SHA1, "226247b40160f2892fa4c7851b5b913d5d10912d");
		Hash sha256 = new Hash(Hash.Algorithm.SHA_256,
				"09a72795a920c1a9c0209cfb8395f8d97089832d249cba8c0938a3423b3ed1d1");
		extRef.setHashes(Arrays.asList(md5, sha1, sha256));

		Component component = new Component();
		component.setGroup("org.example");
		component.setName("mylibrary");
		component.setType(Component.Type.LIBRARY);
		component.setVersion("1.0.0");
		component.addExternalReference(extRef);

		Bom bom = new Bom();
		bom.addComponent(component);

		BomXmlGenerator xmlGenerator = SBOMApplication.createBomXMLGenerator(CycloneDxSchema.Version.VERSION_15, bom);
		String xmlString = xmlGenerator.toXmlString();
		System.out.println(xmlString);

		BomJsonGenerator jsonGenerator = BomGeneratorFactory.createJson(CycloneDxSchema.Version.VERSION_15, bom);
		String jsonString = jsonGenerator.toJsonString();
		System.out.println(jsonString);
	}

}
