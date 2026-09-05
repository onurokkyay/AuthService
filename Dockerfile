# ---- Build stage ----
FROM eclipse-temurin:25-jdk-alpine AS build
WORKDIR /workspace

# Cache the Gradle distribution and dependencies across builds.
COPY gradlew ./
COPY gradle ./gradle
COPY build.gradle settings.gradle gradle.properties ./
RUN ./gradlew --no-daemon dependencies > /dev/null 2>&1 || true

COPY config ./config
COPY src ./src
RUN ./gradlew --no-daemon bootJar -x test

# ---- Layer extraction for image caching ----
FROM eclipse-temurin:25-jre-alpine AS extract
WORKDIR /extract
COPY --from=build /workspace/build/libs/auth-service.jar app.jar
RUN java -Djarmode=tools -jar app.jar extract --layers --destination extracted

# ---- Runtime ----
FROM eclipse-temurin:25-jre-alpine
WORKDIR /app

RUN addgroup -S auth && adduser -S auth -G auth
USER auth

COPY --from=extract /extract/extracted/dependencies/ ./
COPY --from=extract /extract/extracted/spring-boot-loader/ ./
COPY --from=extract /extract/extracted/snapshot-dependencies/ ./
COPY --from=extract /extract/extracted/application/ ./

EXPOSE 8081

# `java -jar app.jar`, not JarLauncher.
#
# The extract step uses `-Djarmode=tools`, Spring Boot 3.3+'s replacement for
# `-Djarmode=layertools`, and only the old mode suits JarLauncher: layertools exploded the fat
# jar so the loader classes sat on the classpath. `tools` writes a thin jar whose manifest names
# the real main class and points `Class-Path` at `lib/`, and leaves `spring-boot-loader/` empty --
# so JarLauncher is not in the image and the container dies on start while the build stays green.
#
# The layer copies above are unchanged and still worth having: `dependencies/` lands as
# `/app/lib/` and rebuilds only when a dependency moves.
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]
