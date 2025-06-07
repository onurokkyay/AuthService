# ---- Stage 1: Build the application ----
FROM gradle:8.7-jdk21 AS builder

# Set working directory
WORKDIR /app

# Copy Gradle build files
COPY build.gradle settings.gradle ./
COPY gradle ./gradle

# Download dependencies
RUN gradle build -x test --no-daemon || return 0

# Copy rest of the source code
COPY . .

# Build the Spring Boot application
RUN gradle bootJar -x test --no-daemon

# ---- Stage 2: Create minimal runtime image ----
FROM eclipse-temurin:21-jre

# Set working directory
WORKDIR /app

# Copy the built JAR from builder stage
COPY --from=builder /app/build/libs/*.jar app.jar

# Expose the port your application runs on (change if not 8080)
EXPOSE 8080

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]