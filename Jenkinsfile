pipeline {
  agent { label 'migration' }

   options {
    buildDiscarder(logRotator(numToKeepStr: '10'))
    disableConcurrentBuilds()
    skipDefaultCheckout true
  }

  tools {
    maven 'apache-maven-latest'
    jdk 'temurin-jdk21-latest'
  }

  environment {
    PUBLISH_LOCATION = 'cbi/updates/p2-sbom'
    GITHUB_REPO = 'eclipse-cbi/p2repo-sbom'
  }

  parameters {
    choice(
      name: 'BUILD_TYPE',
      choices: ['nightly', 'milestone', 'release'],
      description: '''
        Choose the type of build.
        Note that a release build will not promote the build, but rather will promote the most recent milestone build.
        '''
    )

    booleanParam(
      name: 'PROMOTE',
      defaultValue: false,
      description: 'Whether to promote the build to the download server.'
    )

    booleanParam(
      name: 'ARCHIVE',
      defaultValue: false,
      description: 'Whether to archive the workspace.'
    )
  }

  stages {
    stage('Display Parameters') {
      steps {
        echo "BUILD_TYPE=${params.BUILD_TYPE}"
        echo "PROMOTE=${params.PROMOTE}"
        echo "ARCHIVE=${params.ARCHIVE}"
        script {
          env.PROMOTE = params.PROMOTE
          env.BUILD_TYPE = params.BUILD_TYPE
        }
      }
    }

    stage('Git Checkout') {
      steps {
        script {
          def gitVariables = checkout(
            poll: false,
            scm: [
              $class: 'GitSCM',
              branches: [[name: '*/main']],
              doGenerateSubmoduleConfigurations: false,
              extensions: [[$class: 'RelativeTargetDirectory', relativeTargetDir: 'p2repo-sbom']],
              submoduleCfg: [],
              userRemoteConfigs: [[url: "https://github.com/${GITHUB_REPO}.git"]]
            ]
          )

          echo "$gitVariables"
          env.GIT_COMMIT = gitVariables.GIT_COMMIT
        }
      }
    }

    stage('Build Tools and Products') {
      steps {
        sshagent(['projects-storage.eclipse.org-bot-ssh']) {
          dir('p2repo-sbom/releng/org.eclipse.cbi.p2repo.sbom.releng.parent') {
            sh '''
              pwd
              if [[ $PROMOTE == false ]]; then
                promotion_argument='-Dorg.eclipse.justj.p2.manager.args='
              fi
              mvn \
                --no-transfer-progress\
                $promotion_argument \
                -Dorg.eclipse.storage.user=genie.cbi \
                -Dorg.eclipse.justj.p2.manager.build.url=$JOB_URL \
                -Dorg.eclipse.download.location.relative=$PUBLISH_LOCATION \
                -Dorg.eclipse.justj.p2.manager.relative= \
                -Dbuild.type=$BUILD_TYPE \
                -Dgit.commit=$GIT_COMMIT \
                -Dbuild.id=$BUILD_NUMBER \
                -DskipTests=false \
                -Peclipse-sign \
                -Ppromote \
                clean \
                verify
              '''
          }
        }
      }
    }

    stage('Archive Results') {
      when {
        expression {
          params.ARCHIVE
        }
      }
      steps {
        archiveArtifacts 'p2repo-sbom/**'
      }
    }
  }

  post {
    failure {
      mail to: 'ed.merks@gmail.com',
      subject: "[CBI p2 SBOM] Build Failure ${currentBuild.fullDisplayName}",
      mimeType: 'text/html',
      body: "Project: ${env.JOB_NAME}<br/>Build Number: ${env.BUILD_NUMBER}<br/>Build URL: ${env.BUILD_URL}<br/>Console: ${env.BUILD_URL}/console"
    }

    fixed {
      mail to: 'ed.merks@gmail.com',
      subject: "[CBI p2 SBOM] Back to normal ${currentBuild.fullDisplayName}",
      mimeType: 'text/html',
      body: "Project: ${env.JOB_NAME}<br/>Build Number: ${env.BUILD_NUMBER}<br/>Build URL: ${env.BUILD_URL}<br/>Console: ${env.BUILD_URL}/console"
    }

    cleanup {
      deleteDir()
    }
  }
}