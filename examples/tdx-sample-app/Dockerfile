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

# Add intel USER
ARG USERNAME=intel
ARG USER_UID=2000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

# Update the package index and install essential packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    git \
    openjdk-17-jdk

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

RUN apt-get update; \
    apt-get upgrade -y; \
    apt-get autoremove -y; \
    apt-get install -y --no-install-recommends gnupg wget

# Installing TDX sdk
ARG DCAP_VERSION
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' > /etc/apt/sources.list.d/intel-sgx.list
RUN curl https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key -o /tmp/intel-sgx-deb.key; \
    apt-key add /tmp/intel-sgx-deb.key; \
    rm /tmp/intel-sgx-deb.key

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libtdx-attest-dev=${DCAP_VERSION} \
        libtdx-attest=${DCAP_VERSION}

WORKDIR /app

# Copy the project files and directories to the container image
COPY . .

# Set USER permissions for /app required for maven
RUN chown -R $USERNAME:$USERNAME /app

# Set USER to intel
USER $USERNAME

# Set custom maven repository settings since /root is not accessible by USER
# Proxy settings are to be reset in new maven repository
ENV MAVEN_CONFIG /home/intel/.m2

# Set Maven proxy settings
ARG MAVEN_PROXY_HOST
ARG MAVEN_PROXY_PORT

# Create /home/intel/.m2/settings.xml file with proxy settings added if MAVEN_PROXY_HOST/MAVEN_PROXY_PORT are set
RUN if [ -n "${MAVEN_PROXY_HOST}" -a -n "${MAVEN_PROXY_PORT}" ]; then \
        mkdir -p /home/intel/.m2 && \
        echo "<settings><proxies><proxy><id>example-proxy</id><active>true</active><protocol>http</protocol><host>${MAVEN_PROXY_HOST}</host><port>${MAVEN_PROXY_PORT}</port></proxy></proxies></settings>" > /home/intel/.m2/settings.xml; \
    else \
        echo "Proxy not set, using default system env"; \
    fi

# Build the application
RUN mvn -X -e clean compile install package

# Change WORKDIR to Sample App directory
WORKDIR /app/examples/tdx-sample-app

# Compile TDX Sample App
RUN mvn compile

# Run TDX Sample App
CMD ["mvn", "-s", "/home/intel/.m2/settings.xml", "exec:java", "-Dexec.mainClass=com.intel.trustauthority.tdxsampleapp.SampleApp"]
