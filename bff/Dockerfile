# syntax=docker/dockerfile:1
#   docker build -f bff/Dockerfile bff

FROM bellsoft/liberica-openjdk-debian:25 AS build
WORKDIR /src
COPY . .
RUN sed -i 's/\r$//' gradlew && chmod +x gradlew
RUN --mount=type=cache,target=/root/.gradle \
    ./gradlew --no-daemon bootJar -x test \
 && cp build/libs/*-SNAPSHOT.jar /app.jar

FROM bellsoft/liberica-openjre-alpine:27
# Alpine, not Debian: the scan flagged six HIGH libexpat CVEs that Debian 12's
# archive had not yet shipped a package for, so `apt-get upgrade` could not fix
# them. Alpine's runtime image carries far fewer packages to be flagged at all.
# `apk upgrade` still pulls in any fixes published since the base was built.
RUN apk upgrade --no-cache
RUN addgroup -S -g 10001 app && adduser -S -u 10001 -G app -H -s /sbin/nologin app
COPY --from=build /app.jar /app/app.jar
USER 10001:10001
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-XX:+ExitOnOutOfMemoryError", "-jar", "/app/app.jar"]
