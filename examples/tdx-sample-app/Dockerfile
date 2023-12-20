# Use the official Ubuntu base image
ARG UBUNTU_VERSION
FROM ubuntu:$UBUNTU_VERSION

# Set DEBIAN_FRONTEND to non-interactive
ENV DEBIAN_FRONTEND=noninteractive

# Update the package index and install essential packages
RUN apt-get update && \
    apt-get install -y \
    curl \
    git \
    openjdk-17-jdk

# Set up environment variables for Java
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV PATH=$PATH:$JAVA_HOME/bin

# Install Maven
ARG MAVEN_VERSION
ENV MAVEN_VERSION=$MAVEN_VERSION
ENV MAVEN_HOME=/opt/maven

RUN curl -fsSL https://archive.apache.org/dist/maven/maven-3/${MAVEN_VERSION}/binaries/apache-maven-${MAVEN_VERSION}-bin.tar.gz | tar xzf - -C /opt/ \
    && ln -s /opt/apache-maven-${MAVEN_VERSION} /opt/maven \
    && ln -s /opt/maven/bin/mvn /usr/local/bin

# Set the working directory in the container
WORKDIR /app

# Set Maven proxy settings
ARG MAVEN_PROXY_HOST
ARG MAVEN_PROXY_PORT

# Create /root/.m2/settings.xml file with proxy settings added if MAVEN_PROXY_HOST/MAVEN_PROXY_PORT are set
RUN if [ -n "${MAVEN_PROXY_HOST}" -a -n "${MAVEN_PROXY_PORT}" ]; then \
        mkdir -p /root/.m2 && \
        echo "<settings><proxies><proxy><id>example-proxy</id><active>true</active><protocol>http</protocol><host>${MAVEN_PROXY_HOST}</host><port>${MAVEN_PROXY_PORT}</port></proxy></proxies></settings>" > /root/.m2/settings.xml \
    else \
        echo "Proxy not set, using default system env"; \
    fi

# Installing TDX sdk essentials
RUN apt-get update; \
    apt-get upgrade -y; \
    apt-get autoremove -y; \
    apt-get install -y gnupg wget

# Installing TDX sdk
ARG DCAP_VERSION
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' > /etc/apt/sources.list.d/intel-sgx.list
RUN curl https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key -o /tmp/intel-sgx-deb.key; \
    apt-key add /tmp/intel-sgx-deb.key; \
    rm /tmp/intel-sgx-deb.key
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libtdx-attest-dev=${DCAP_VERSION} \
        libtdx-attest=${DCAP_VERSION} \
        libcurl4-openssl-dev \
        libcurl4 \
	    libssl1.1

# Copy the project files and directories to the container image
COPY pom.xml .

# Copy src code
COPY connector connector
COPY sgx sgx
COPY tdx tdx
COPY examples examples
COPY resources resources

# Build the application
RUN mvn -X -e clean compile install package

# Change WORKDIR to Sample App directory
WORKDIR /app/examples/tdx-sample-app

# Compile TDX Sample App
RUN javac -cp /root/.m2/repository/org/apache/logging/log4j/log4j-api/2.17.1/log4j-api-2.17.1.jar:/root/.m2/repository/org/apache/logging/log4j/log4j-core/2.17.1/log4j-core-2.17.1.jar:/root/.m2/repository/org/bouncycastle/bcprov-jdk15on/1.68/bcprov-jdk15on-1.68.jar:/root/.m2/repository/com/fasterxml/jackson/core/jackson-annotations/2.13.0/jackson-annotations-2.13.0.jar:/root/.m2/repository/com/fasterxml/jackson/core/jackson-databind/2.13.0/jackson-databind-2.13.0.jar:/root/.m2/repository/com/fasterxml/jackson/core/jackson-core/2.13.0/jackson-core-2.13.0.jar:/root/.m2/repository/net/java/dev/jna/jna/5.9.0/jna-5.9.0.jar:/root/.m2/repository/com/google/code/gson/gson/2.9.0/gson-2.9.0.jar:/root/.m2/repository/io/jsonwebtoken/jjwt/0.12.3/jjwt-0.12.3.jar:/root/.m2/repository/io/jsonwebtoken/jjwt-impl/0.11.2/jjwt-impl-0.11.2.jar:/root/.m2/repository/io/jsonwebtoken/jjwt-api/0.11.2/jjwt-api-0.11.2.jar:/root/.m2/repository/io/jsonwebtoken/jjwt-jackson/0.11.2/jjwt-jackson-0.11.2.jar:/root/.m2/repository/com/nimbusds/nimbus-jose-jwt/9.10/nimbus-jose-jwt-9.10.jar:/root/.m2/repository/com/fasterxml/jackson/core/jackson-core/2.13.0/jackson-core-2.13.0.jar:../../connector/target/connector-1.0.0.jar:../../tdx/target/tdx-1.0.0.jar TdxSampleApp.java

# Run TDX Sample App
CMD ["java", "-cp", "/root/.m2/repository/org/apache/logging/log4j/log4j-api/2.17.1/log4j-api-2.17.1.jar:/root/.m2/repository/org/apache/logging/log4j/log4j-core/2.17.1/log4j-core-2.17.1.jar:/root/.m2/repository/org/bouncycastle/bcprov-jdk15on/1.68/bcprov-jdk15on-1.68.jar:/root/.m2/repository/com/fasterxml/jackson/core/jackson-annotations/2.13.0/jackson-annotations-2.13.0.jar:/root/.m2/repository/com/fasterxml/jackson/core/jackson-databind/2.13.0/jackson-databind-2.13.0.jar:/root/.m2/repository/com/fasterxml/jackson/core/jackson-core/2.13.0/jackson-core-2.13.0.jar:/root/.m2/repository/net/java/dev/jna/jna/5.9.0/jna-5.9.0.jar:/root/.m2/repository/com/google/code/gson/gson/2.9.0/gson-2.9.0.jar:/root/.m2/repository/io/jsonwebtoken/jjwt/0.12.3/jjwt-0.12.3.jar:/root/.m2/repository/io/jsonwebtoken/jjwt-impl/0.11.2/jjwt-impl-0.11.2.jar:/root/.m2/repository/io/jsonwebtoken/jjwt-api/0.11.2/jjwt-api-0.11.2.jar:/root/.m2/repository/io/jsonwebtoken/jjwt-jackson/0.11.2/jjwt-jackson-0.11.2.jar:/root/.m2/repository/com/nimbusds/nimbus-jose-jwt/9.10/nimbus-jose-jwt-9.10.jar:/root/.m2/repository/com/fasterxml/jackson/core/jackson-core/2.13.0/jackson-core-2.13.0.jar:../../connector/target/connector-1.0.0.jar:../../tdx/target/tdx-1.0.0.jar:./", "TdxSampleApp"]
