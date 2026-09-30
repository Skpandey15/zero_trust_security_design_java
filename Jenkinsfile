// Pipeline for the zero-trust platform.
//
// Runs on disposable Kubernetes pod agents (no builds on the controller).
//   build+test -> package (Kaniko, no Docker socket) -> scan (Trivy)
//   -> deploy (main only, dry-run first) -> rollout verification
//
// See deploy/README.md for how Jenkins, the registry and the agent RBAC are set up.

pipeline {
  agent {
    kubernetes {
      defaultContainer 'jnlp'
      yaml '''
apiVersion: v1
kind: Pod
spec:
  serviceAccountName: jenkins-agent
  containers:
    # Gradle 9.7 cannot itself run on JDK 27, so it runs on 25 and the toolchain
    # fetches 27 to compile. The download lands in the cached volume.
    - name: jdk
      image: bellsoft/liberica-openjdk-debian:25
      command: [sleep]
      args: [infinity]
      env:
        - { name: GRADLE_USER_HOME, value: /cache/gradle }
      resources:
        requests: { cpu: 500m, memory: 512Mi }
        limits: { memory: 3Gi }
      volumeMounts:
        - { name: gradle-cache, mountPath: /cache }
    - name: node
      image: node:24-alpine
      command: [sleep]
      args: [infinity]
      resources:
        requests: { cpu: 250m, memory: 256Mi }
        limits: { memory: 1Gi }
    - name: kaniko
      image: gcr.io/kaniko-project/executor:v1.23.2-debug
      command: [/busybox/cat]
      tty: true
      resources:
        requests: { cpu: 250m, memory: 256Mi }
        limits: { memory: 2Gi }
    - name: trivy
      image: aquasec/trivy:latest
      command: [sleep]
      args: [infinity]
      resources:
        requests: { cpu: 100m, memory: 256Mi }
        limits: { memory: 1Gi }
    - name: tools
      image: alpine/k8s:1.37.1
      command: [sleep]
      args: [infinity]
      resources:
        requests: { cpu: 50m, memory: 64Mi }
        limits: { memory: 256Mi }
  volumes:
    - name: gradle-cache
      persistentVolumeClaim: { claimName: gradle-cache }
'''
    }
  }

  options {
    timeout(time: 60, unit: 'MINUTES')
    disableConcurrentBuilds()        // one shared Gradle cache, one deploy target
    buildDiscarder(logRotator(numToKeepStr: '20'))
    timestamps()
  }

  parameters {
    booleanParam(name: 'SCAN_GATE', defaultValue: true,
                 description: 'Fail the build on fixable HIGH/CRITICAL image vulnerabilities')
  }

  environment {
    // Kaniko pushes by cluster DNS; the nodes pull the same registry as localhost:30500.
    PUSH_REGISTRY = 'registry.registry.svc.cluster.local:5000'
    PULL_REGISTRY = 'localhost:30500'
    SERVICES_JVM  = 'authorization-server resource-server bff'
  }

  stages {

    stage('Init') {
      steps {
        sh 'git config --global --add safe.directory "$WORKSPACE"'
        script {
          env.IMAGE_TAG = sh(returnStdout: true, script: 'git rev-parse --short=12 HEAD').trim()
          // The gate is ON unless someone explicitly turns it off. On a branch's first
          // run Jenkins has not registered the parameter yet, so params.SCAN_GATE is
          // null - and null must not mean "off".
          env.SCAN_EXIT = (params.SCAN_GATE == null || params.SCAN_GATE) ? '1' : '0'
        }
        echo "image tag ${env.IMAGE_TAG}, branch ${env.BRANCH_NAME}"
      }
    }

    stage('Build and test') {
      parallel {
        stage('JVM services') {
          steps {
            container('jdk') {
              sh '''
                set -e
                (cd backend && ./gradlew --no-daemon build)
                (cd bff     && ./gradlew --no-daemon build)
              '''
            }
          }
        }
        stage('Frontend') {
          steps {
            container('node') {
              sh '''
                set -e
                cd frontend
                npm ci
                npm run typecheck
                npm run build
              '''
            }
          }
        }
      }
    }

    stage('Validate manifests') {
      steps {
        container('tools') {
          // Server-side dry run: the API server checks the real schemas
          // (including cert-manager and Traefik CRDs) and runs admission,
          // which kubeconform cannot do. Nothing is changed.
          sh '''
            DRY_RUN=1 IMAGE_REGISTRY="${PULL_REGISTRY}/" IMAGE_TAG="${IMAGE_TAG}" \
              deploy/scripts/apply.sh
          '''
        }
      }
    }

    stage('Package') {
      steps {
        // Stage clean, minimal build contexts so only what ships is in the image.
        sh '''
          set -e
          rm -rf pkg && mkdir -p pkg/authorization-server pkg/resource-server pkg/bff pkg/frontend
          cp backend/authorization-server/build/libs/*-SNAPSHOT.jar pkg/authorization-server/app.jar
          cp backend/resource-server/build/libs/*-SNAPSHOT.jar      pkg/resource-server/app.jar
          cp bff/build/libs/*-SNAPSHOT.jar                          pkg/bff/app.jar
          cp -r frontend/dist pkg/frontend/dist
          cp frontend/nginx.conf pkg/frontend/nginx.conf
        '''
        // Kaniko builds in userspace: no Docker socket, no privileged pod.
        container(name: 'kaniko', shell: '/busybox/sh') {
          sh '''
            set -e
            for svc in ${SERVICES_JVM}; do
              /kaniko/executor --context "dir://${WORKSPACE}/pkg/${svc}" \
                --dockerfile "${WORKSPACE}/deploy/docker/Dockerfile.java" \
                --destination "${PUSH_REGISTRY}/zero-trust/${svc}:${IMAGE_TAG}" \
                --insecure --skip-tls-verify --cache=false
            done
            /kaniko/executor --context "dir://${WORKSPACE}/pkg/frontend" \
              --dockerfile "${WORKSPACE}/deploy/docker/Dockerfile.frontend" \
              --destination "${PUSH_REGISTRY}/zero-trust/frontend:${IMAGE_TAG}" \
              --insecure --skip-tls-verify --cache=false
          '''
        }
      }
    }

    stage('Scan images') {
      steps {
        container('trivy') {
          sh '''
            EXIT=${SCAN_EXIT}
            for svc in ${SERVICES_JVM} frontend; do
              trivy image --insecure --no-progress --ignore-unfixed \
                --severity HIGH,CRITICAL --exit-code ${EXIT} \
                "${PUSH_REGISTRY}/zero-trust/${svc}:${IMAGE_TAG}"
            done
          '''
        }
      }
    }

    stage('Deploy') {
      when { branch 'main' }
      steps {
        container('tools') {
          sh '''
            set -e
            IMAGE_REGISTRY="${PULL_REGISTRY}/" IMAGE_TAG="${IMAGE_TAG}" deploy/scripts/apply.sh
            for d in authorization-server resource-server bff frontend; do
              kubectl -n zero-trust rollout status "deploy/${d}" --timeout=300s
            done
          '''
        }
      }
    }
  }

  post {
    always {
      junit allowEmptyResults: true, testResults: '**/build/test-results/test/*.xml'
    }
  }
}
