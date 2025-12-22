# Maven/Jenkins Integration

Under construction.

## Projects Using the CBI p2 SBOM Generator


### Orbit

Orbit uses a self-contained [Jenkins pipeline](https://github.com/eclipse-orbit/orbit-simrel/blob/main/orbit-aggregation/OrbitAggregationSBOM.jenkinsfile)
to generate SBOMs published to [sbom.eclipse.org](https://sbom.eclipse.org/projects/a598db3e-3857-4ef2-a8ad-c75db18cdd35/collectionprojects).

- [orbit-sbom](https://ci.eclipse.org/orbit/job/orbit-sbom/)


### SimRel

SimRel uses a self-contained [Jenkins pipeline](https://github.com/eclipse-simrel/simrel.build/blob/main/Jenkinsfile-sbom/)
to generate SBOMs published to [sbom.eclipse.org](https://sbom.eclipse.org/projects/e1ac111b-8567-403c-8df7-950588c102e9/collectionprojects).

- [simrel.sbom](https://ci.eclipse.org/simrel/job/simrel.sbom/)

The job provides more details and relevant links in its description.
