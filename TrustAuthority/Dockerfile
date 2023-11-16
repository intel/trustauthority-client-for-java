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

# Print Maven and Java versions to verify installation
RUN java -version
RUN mvn -v

# Set the working directory in the container
WORKDIR /app

# Set Maven proxy settings
ARG PROXY_HOST
ARG PROXY_PORT
ARG MAVEN_PROXY_HOST=$PROXY_HOST
ARG MAVEN_PROXY_PORT=$PROXY_PORT

# Create /root/.m2/settings.xml file with proxy settings added
RUN mkdir -p /root/.m2 && \
    echo "<settings><proxies><proxy><id>example-proxy</id><active>true</active><protocol>http</protocol><host>${MAVEN_PROXY_HOST}</host><port>${MAVEN_PROXY_PORT}</port></proxy></proxies></settings>" > /root/.m2/settings.xml

# Copy the project files and directories to the container image
COPY pom.xml .

# This first build is to avoid all packages getting freshly installed
# whenever there is a change in src files
RUN mvn -X -e clean compile install package

# Copy src code
COPY src src

# Build the application
RUN mvn -X -e clean compile install package

# Expose the port the SampleAppServer application runs on
EXPOSE 8080
