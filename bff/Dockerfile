# syntax=docker/dockerfile:1
#   docker build -f bff/Dockerfile bff

FROM bellsoft/liberica-openjdk-debian:25 AS build
WORKDIR /src
COPY . .
RUN sed -i 's/\r$//' gradlew && chmod +x gradlew
RUN --mount=type=cache,target=/root/.gradle \
    ./gradlew --no-daemon bootJar -x test \
 && cp build/libs/*-SNAPSHOT.jar /app.jar

FROM bellsoft/liberica-openjre-debian:27
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid app --no-create-home app
COPY --from=build /app.jar /app/app.jar
USER 10001:10001
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-XX:+ExitOnOutOfMemoryError", "-jar", "/app/app.jar"]
