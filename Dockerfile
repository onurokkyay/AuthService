# 1. Build stage: Use Maven with JDK 21 to build the project
FROM maven:3.9.0-eclipse-temurin-21 AS build

WORKDIR /app

# Copy pom.xml and download dependencies first to leverage Docker cache
COPY pom.xml .
RUN mvn dependency:go-offline

# Copy source code to container
COPY src ./src

# Build the Spring Boot jar, skipping tests for faster build
RUN mvn clean package -DskipTests

# 2. Run stage: Use a minimal JRE 21 image to run the built jar
FROM eclipse-temurin:21-jre

WORKDIR /app

# Copy the built jar from the build stage
COPY --from=build /app/target/*.jar auth-service.jar

# Expose port 8081 (default port for auth service)
EXPOSE 8081

# Run the Spring Boot application
ENTRYPOINT ["java", "-jar", "auth-service.jar"]