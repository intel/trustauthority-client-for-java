###########################################
# Copyright (c) 2023-2024 Intel Corporation
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
###########################################

# Use the official Ubuntu base image
ARG UBUNTU_VERSION
FROM ubuntu:$UBUNTU_VERSION

# Set DEBIAN_FRONTEND to non-interactive
ENV DEBIAN_FRONTEND=noninteractive


# Update the package index and install essential packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    openjdk-17-jdk-headless

# Set up environment variables for Java
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV PATH=$PATH:$JAVA_HOME/bin

# Install Maven
ARG MAVEN_VERSION
ENV MAVEN_HOME=/opt/maven

RUN curl -fsSL https://archive.apache.org/dist/maven/maven-3/${MAVEN_VERSION}/binaries/apache-maven-${MAVEN_VERSION}-bin.tar.gz | tar xzf - -C /opt/ \
    && ln -s /opt/apache-maven-${MAVEN_VERSION} /opt/maven \
    && ln -s /opt/maven/bin/mvn /usr/local/bin

# Set Maven proxy settings
ARG MAVEN_PROXY_HOST
ARG MAVEN_PROXY_PORT

# Create /root/.m2/settings.xml file with proxy settings added if MAVEN_PROXY_HOST/MAVEN_PROXY_PORT are set
RUN if [ -n "${MAVEN_PROXY_HOST}" -a -n "${MAVEN_PROXY_PORT}" ]; then \
        mkdir -p /root/.m2 && \
        echo "<settings><proxies><proxy><id>example-proxy</id><active>true</active><protocol>http</protocol><host>${MAVEN_PROXY_HOST}</host><port>${MAVEN_PROXY_PORT}</port></proxy></proxies></settings>" > /root/.m2/settings.xml; \
    else \
        echo "Proxy not set, using default system env"; \
    fi

WORKDIR /app

# Copy the project files and directories to the container image
COPY . .

# Build the application
RUN mvn -e install -DskipTests

# Change WORKDIR to Sample App directory
WORKDIR /app/examples/tdx-sample-app

# Compile TDX Sample App and build executable jar file
RUN mvn compile assembly:single 

# Run TDX Sample App
CMD ["java","-jar","target/tdxsampleapp-1.1.0-jar-with-dependencies.jar"]
