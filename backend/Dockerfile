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

FROM bellsoft/liberica-openjre-debian:27
# Pull in Debian security fixes published since the base image was built (the
# image scan flagged libpcre2 HIGH CVEs that have a fixed package).
RUN apt-get update && apt-get upgrade -y --no-install-recommends  && rm -rf /var/lib/apt/lists/*
# Fixed non-root uid/gid: matches runAsUser in the Kubernetes manifests.
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid app --no-create-home app
COPY --from=build /app.jar /app/app.jar
USER 10001:10001
WORKDIR /app
EXPOSE 8080
# Container-aware heap; exit on OOM so Kubernetes restarts rather than limps.
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-XX:+ExitOnOutOfMemoryError", "-jar", "/app/app.jar"]
