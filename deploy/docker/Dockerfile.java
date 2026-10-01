# Packaging-only image for a Spring Boot fat jar that CI has ALREADY built and
# tested. Jenkins builds the jar once (with a warm Gradle cache), then Kaniko
# packages it here - the jar that was tested is the jar that ships.
#
# backend/Dockerfile and bff/Dockerfile build from source instead; they exist
# for `deploy/scripts/build-images.sh` on a laptop. Keep the runtime half of
# all three in step.
#
#   context: a directory containing  app.jar
FROM bellsoft/liberica-openjre-alpine:27
# Alpine, not Debian: the scan flagged six HIGH libexpat CVEs that Debian 12's
# archive had not yet shipped a package for, so `apt-get upgrade` could not fix
# them. Alpine's runtime image carries far fewer packages to be flagged at all.
# `apk upgrade` still pulls in any fixes published since the base was built.
RUN apk upgrade --no-cache
RUN addgroup -S -g 10001 app && adduser -S -u 10001 -G app -H -s /sbin/nologin app
COPY app.jar /app/app.jar
USER 10001:10001
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-XX:+ExitOnOutOfMemoryError", "-jar", "/app/app.jar"]
