# CBI p2 SBOM

An Eclipse application based on the 
[Eclipse Platform](https://eclipse.dev/eclipse/)
is an
[OSGi](https://docs.osgi.org/)
application composed from
[bundles](https://docs.osgi.org/specification/osgi.core/8.0.0/framework.module.html#d0e2803)
as the primary building blocks.
The Platform's OSGi implementation,
[Equinox](https://github.com/eclipse-equinox/),
supports a provisioning framework
[p2](https://help.eclipse.org/latest/index.jsp?topic=%2Forg.eclipse.platform.doc.isv%2Fguide%2Fp2_api_overview.htm)
for managing p2 repositories that provide access to the application units,
e.g., the application bundles,
for provisioning application installations from those units.

A Software Bill of Material, an SBOM,
is a formal inventory of a software application's components,
including metadata about those components as well as dependencies between those components.
To produce an SBOM for an Eclipse application,
the building blocks of the application must be mapped onto a formal SBOM model.
The CBI p2 SBOM generator uses 
[ClyconeDX](https://cyclonedx.org/)
as for the formal representation,
currently specification version
[1.6](https://cyclonedx.org/specification/overview/).

OSGi provides a rich metadata for each bundle,
e.g., bundle symbolic name, bundle version, and so on.
In terms of dependencies,
each bundle declares its provided
[capabilities](https://docs.osgi.org/specification/osgi.core/8.0.0/framework.module.html#d0e2870)
and specifies
[requirements](https://docs.osgi.org/specification/osgi.core/8.0.0/framework.module.html#d0e3015)
relative to such capabilities.
The p2 framework provides analgous concepts,
projecting the OSGi metadata as p2 metadata.
This information is a rich source of details from which to derive an SBOM.
That being said,
there is a significant impedence mismatch between the concept of OSGi/p2 requirements versus the concept of SBOM dependencies.


## Application Units

An Eclipse application comprises additional building blocks
as supported by the Eclipse Plug-in Development Environment,
[PDE](https://projects.eclipse.org/projects/eclipse.pde):
- A [plug-in](https://help.eclipse.org/latest/index.jsp?topic=%2Forg.eclipse.pde.doc.user%2Fconcepts%2Fplugin.htm)
  is effectively just a synonym for a bundle.
- A [fragment](https://help.eclipse.org/latest/index.jsp?topic=%2Forg.eclipse.pde.doc.user%2Fconcepts%2Ffragment.htm&cp%3D4_1_2)
  is a special type of bundle that extends a so-call host bundle, typically with a platform-native implementation.
- A [feature](https://help.eclipse.org/latest/index.jsp?topic=%2Forg.eclipse.pde.doc.user%2Fconcepts%2Ffeature.htm&cp%3D4_1_1)
  is a collection of dependencies on plug-ins, fragments, and other features.
  It is intended as a user-facing unit that provides support for some high-level functionality that the user may choose to install in an application
- A [product](https://help.eclipse.org/latest/index.jsp?topic=%2Forg.eclipse.pde.doc.user%2Fconcepts%2Fproduct.htm&cp%3D4_1_4)
  is a description of a complete standalone Eclipse application,
  specifying the bundles, fragments, and features to be installed, program argments, JVM arguments, branding details, and so on.
All the building blocks are mapped onto p2 and made available via p2 repositories.

## p2 Repositories

The p2 framework supports two types of repository, often colocated at the same URL:
- Metadata 
  - This provide acccess to
    [installable units](https://eclipse.dev/eclipse/markdown/?file=eclipse-equinox/p2/master/docs/Installable_Units.md)
    which specify metadata about all the units available for provisioninioning an application,
    including the unit's provided capabilities as well as it's required capabilities.
    Each installable unit is uniquely identified by its ID and version.
- Artifact 
  - This provides access to the actual physical artifacts, e.g., jars and binaries.
    Each artifact is uniquely identified by its artifact key.

### p2 Engine

When an application is installed or updated by the p2 engine,
a request to add, remove, or update installable units is specified,
and one or more metadata repositories is made available to satisfy that request.
The engine builds a so-called plan using
[sat4j](https://www.sat4j.org/)
and then executes that plan.

An installable unit typically, but not always, has an associated artifact specified by an artifact key.
For the enine to execute the plan,
one or more artifact repositories providing access to the corresponding artifact of each installable unit in the plan must be made available.
An installable unit can also specify touchpoints,
i.e., instructions for how to process the specified artifact,
or even instuctions for how to modify the target installation.

### Installations

The building block that comprise an Eclipde product installation,
as provisioned by p2,
is defined by the following:
- A profile that specifies the installable units of the installation, which is logically a p2 metadata repository.
- An artifact repository that specifies the location of each corresponding artifact of each installable unit in that installation.

In this sense,
an installation is logically equivalent to a pair p2 repositories.
The CBI p2 SBOM generator exploits this equivalence,
making it possible to generate an SBOM for p2 repositories and Eclipse installations with the same underlying implementation logic.

## SBOM Component Mapping

Given the typical close correspondence between installable unit and artifact,
and given SBOMs focus on components as artifacts,
it is beneficial to unify these two during the mapping process.


## Tycho SBOM

The Tycho 5.x release directly supports
[CycloneDX SBOM generation](https://github.com/eclipse-tycho/tycho/blob/tycho-5.0.x/RELEASE_NOTES.md#support-for-cyclonedx-maven-plugin)
via the 
[tycho-sbom](https://github.com/eclipse-tycho/tycho/tree/main/tycho-sbom)
mojo.
It provides
[an example](https://github.com/eclipse-tycho/tycho/tree/main/tycho-its/projects/sbom)
of how to use it.
Applying this to the Eclipse Installer has provided a useful basis for comparing the SBOMs generated Tycho with that generated by the CBI p2 SBOM generator.

### Under Construction

The Tycho sboms don't properly use the bom-ref of the component for specifying dependencies using two different styles,
either the pgk:maven or pkg:p2 for a given component.
Also has references to components that don't exist, e.g., .source bundles.
In the end, we can't really even a hack a workaround because the SBOM does not contain the BSN of the component, only the maven coordinates.
The Tycho sbom seem to have odd components that aren't actually in the product repository,
e.g., com.sun.xml.bind,
probably as a result of resolving package requirements to all possible providers in the target platform,
also lots of *.source bundles that aren't in the product.
More care must be taken when generating PURLs that in fact the maven artifact has the same hash sums as the p2/local artifact.



