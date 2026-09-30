# Packaging-only image for a Spring Boot fat jar that CI has ALREADY built and
# tested. Jenkins builds the jar once (with a warm Gradle cache), then Kaniko
# packages it here - the jar that was tested is the jar that ships.
#
# backend/Dockerfile and bff/Dockerfile build from source instead; they exist
# for `deploy/scripts/build-images.sh` on a laptop. Keep the runtime half of
# all three in step.
#
#   context: a directory containing  app.jar
FROM bellsoft/liberica-openjre-debian:27
# Pull in Debian security fixes published since the base image was built (the
# image scan flagged libpcre2 HIGH CVEs that have a fixed package).
RUN apt-get update && apt-get upgrade -y --no-install-recommends  && rm -rf /var/lib/apt/lists/*
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid app --no-create-home app
COPY app.jar /app/app.jar
USER 10001:10001
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-XX:+ExitOnOutOfMemoryError", "-jar", "/app/app.jar"]
