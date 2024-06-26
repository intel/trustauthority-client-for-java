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

# Installing SGX sdk essentials
RUN apt-get update; \
    apt-get upgrade -y; \
    apt-get autoremove -y; \
    apt-get install -y --no-install-recommends gnupg wget make

# Installing SGX sdk
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' > /etc/apt/sources.list.d/intel-sgx.list

# Fetch intel-sgx-deb.key
RUN curl https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key -o /tmp/intel-sgx-deb.key; \
    apt-key add /tmp/intel-sgx-deb.key; \
    rm /tmp/intel-sgx-deb.key

RUN apt-get update && apt-get install -y --no-install-recommends build-essential

# Installing Linux SGX sdk
ARG DCAP_VERSION
ARG PSW_VERSION
ARG UBUNTU_VERSION
WORKDIR /opt/intel
RUN wget -q https://download.01.org/intel-sgx/sgx-linux/2.22/distro/ubuntu${UBUNTU_VERSION}-server/sgx_linux_x64_sdk_${PSW_VERSION}.bin; \
    chmod +x sgx_linux_x64_sdk_${PSW_VERSION}.bin; \
    echo 'yes' | ./sgx_linux_x64_sdk_${PSW_VERSION}.bin

# Installing DCAP sdk libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsgx-urts=${PSW_VERSION}-focal1 \
    libsgx-qe3-logic=${DCAP_VERSION} \
    libsgx-pce-logic=${DCAP_VERSION} \
    libsgx-dcap-ql=${DCAP_VERSION} \
    libsgx-dcap-ql-dev=${DCAP_VERSION} \
    libsgx-quote-ex=${PSW_VERSION}-focal1

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
RUN mvn -X -e clean compile install package -DskipTests

# Change WORKDIR to Sample App directory
WORKDIR /app/examples/sgx-sample-app/enclave

# Create the enclave.signed.so
RUN make clean && \
    make

# Change WORKDIR to Sample App directory
WORKDIR /app/examples/sgx-sample-app

# Compile SGX Sample App
RUN mvn compile

# Run SGX Sample App
CMD ["mvn", "-s", "/home/intel/.m2/settings.xml", "exec:java", "-Dexec.mainClass=com.intel.trustauthority.sgxsampleapp.SampleApp"]
