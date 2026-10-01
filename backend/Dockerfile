# syntax=docker/dockerfile:1
# Builds ONE backend module into a runtime image:
#   docker build -f backend/Dockerfile --build-arg MODULE=authorization-server backend
#
# Gradle 9.7 cannot itself run on JDK 27 (its Groovy rejects class version 71), so
# the build stage runs Gradle on JDK 25 and the foojay toolchain resolver fetches
# JDK 27 to compile - cached in the gradle cache mount. The runtime image is 27.
# Java 27 is not in the Temurin image set yet; BellSoft Liberica publishes it.

FROM bellsoft/liberica-openjdk-debian:25 AS build
ARG MODULE
WORKDIR /src
COPY . .
# Windows checkouts can carry CRLF into the wrapper's shebang line.
RUN sed -i 's/\r$//' gradlew && chmod +x gradlew
RUN --mount=type=cache,target=/root/.gradle \
    ./gradlew --no-daemon ":${MODULE}:bootJar" -x test \
 && cp "${MODULE}/build/libs/"*-SNAPSHOT.jar /app.jar

FROM bellsoft/liberica-openjre-alpine:27
# Alpine, not Debian: the scan flagged six HIGH libexpat CVEs that Debian 12's
# archive had not yet shipped a package for, so `apt-get upgrade` could not fix
# them. Alpine's runtime image carries far fewer packages to be flagged at all.
# `apk upgrade` still pulls in any fixes published since the base was built.
RUN apk upgrade --no-cache
# Fixed non-root uid/gid: matches runAsUser in the Kubernetes manifests.
RUN addgroup -S -g 10001 app && adduser -S -u 10001 -G app -H -s /sbin/nologin app
COPY --from=build /app.jar /app/app.jar
USER 10001:10001
WORKDIR /app
EXPOSE 8080
# Container-aware heap; exit on OOM so Kubernetes restarts rather than limps.
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-XX:+ExitOnOutOfMemoryError", "-jar", "/app/app.jar"]
