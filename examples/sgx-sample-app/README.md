# SGX Attestation Sample App
The SGX Attestation Sample App is a Java application that uses the Intel Trust Authority Attestation Java Client libraries
to fetch token from Intel Trust Authority. The application contains an example SGX enclave. When run, 
it collects quote from the enclave and sends it to Intel Trust Authority to retrieve a token.

```
┌────────────────────────────────────────────────┐
│    ┌──────────────────────────────────────┐    │
│    │          Docker Container            │    │
│    │                                      │    │
│    │    ┌──────────────────────────┐      │    │
│    │    │SGX Attestation Sample App│      │    │                ┌────────────────┐
│    │    └──────────────────────────┘      │    │                │                │
│    │                                      │    │                │                │
│    │    ┌──────────────────────────┐      │◄───┼───────────────►│   INTEL TRUST  |
│    │    │     enclave.signed.so    │      │    │                │   AUTHORITY    |
│    │    └──────────────────────────┘      │    │                │   CLIENT       |
│    │                                      │    │                └────────────────┘   
│    │    ┌──────────────────────────┐      |    |                                                  
│    │    |    connector-1.0.0.jar   |      |    |
│    │    └──────────────────────────┘      │    │
│    │                                      │    │              
│    │    ┌──────────────────────────┐      │    │
│    │    │      sgx-1.0.0.jar       |      |    |
│    │    └──────────────────────────┘      │    │
│    │                                      │    │
│    └──────────────────────────────────────┘    │
│                                                │
│                  SGX Host                      │
└────────────────────────────────────────────────┘
```
The diagram above depicts the components used in the SGX Attestation Sample App while running within
a docker container. The SGX Attestation Sample App example can also be run directly on a SGX host (provided
the appropriate dependencies like DCAP have been installed).


## Usage for running SGX Attestation Sample App

### Compile the latest version of `connector` and `sgx` with the following command:

```sh
cd ../../ && \
mvn -X -e clean compile install package && \
cd -
```

### Generate the example signed enclave:

Since the SGX Attestation Sample App requires an enclave to be initialized, run this step to generate a signed enclave:
```sh
cd sgx-example-enclave/enclave/ && \
make && \
cd -
```

### Compile the Sample App with the following command:

Once the above step is complete and the `enclave.signed.so` file is generated, run the below command to compile the `SGX Attestation Sample App`:

```sh
javac -cp ~/.m2/repository/org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar:~/.m2/repository/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar:~/.m2/repository/org/bouncycastle/bcprov-jdk15on/1.68/bcprov-jdk15on-1.68.jar:~/.m2/repository/com/fasterxml/jackson/core/jackson-annotations/2.13.0/jackson-annotations-2.13.0.jar:~/.m2/repository/com/fasterxml/jackson/core/jackson-databind/2.13.0/jackson-databind-2.13.0.jar:~/.m2/repository/com/fasterxml/jackson/core/jackson-core/2.13.0/jackson-core-2.13.0.jar:~/.m2/repository/net/java/dev/jna/jna/5.9.0/jna-5.9.0.jar:~/.m2/repository/com/google/code/gson/gson/2.9.0/gson-2.9.0.jar:~/.m2/repository/io/jsonwebtoken/jjwt/0.12.3/jjwt-0.12.3.jar:~/.m2/repository/io/jsonwebtoken/jjwt-impl/0.11.2/jjwt-impl-0.11.2.jar:~/.m2/repository/io/jsonwebtoken/jjwt-api/0.11.2/jjwt-api-0.11.2.jar:~/.m2/repository/io/jsonwebtoken/jjwt-jackson/0.11.2/jjwt-jackson-0.11.2.jar:~/.m2/repository/com/nimbusds/nimbus-jose-jwt/9.10/nimbus-jose-jwt-9.10.jar:~/.m2/repository/com/fasterxml/jackson/core/jackson-core/2.13.0/jackson-core-2.13.0.jar:../../connector/target/connector-1.0.0.jar:../../sgx/target/sgx-1.0.0.jar SgxSampleApp.java
```

### Run the Sample App with the following command:

Please ensure to set these variables in the environment as a pre-requisite:

```sh
export HTTPS_PROXY_HOST=<HTTPS_PROXY_HOST>
export HTTPS_PROXY_PORT=<HTTPS_PROXY_PORT>
export TRUSTAUTHORITY_REQUEST_ID=<TRUSTAUTHORITY_REQUEST_ID>
export TRUSTAUTHORITY_BASE_URL=<TRUSTAUTHORITY_BASE_URL>
export TRUSTAUTHORITY_API_URL=<TRUSTAUTHORITY_API_URL>
export TRUSTAUTHORITY_API_KEY=<TRUSTAUTHORITY_API_KEY>
```

Run the Sample App after setting the environment variables with the following command:

```sh
java -cp ~/.m2/repository/org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar:~/.m2/repository/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar:~/.m2/repository/org/bouncycastle/bcprov-jdk15on/1.68/bcprov-jdk15on-1.68.jar:~/.m2/repository/com/fasterxml/jackson/core/jackson-annotations/2.13.0/jackson-annotations-2.13.0.jar:~/.m2/repository/com/fasterxml/jackson/core/jackson-databind/2.13.0/jackson-databind-2.13.0.jar:~/.m2/repository/com/fasterxml/jackson/core/jackson-core/2.13.0/jackson-core-2.13.0.jar:~/.m2/repository/net/java/dev/jna/jna/5.9.0/jna-5.9.0.jar:~/.m2/repository/com/google/code/gson/gson/2.9.0/gson-2.9.0.jar:~/.m2/repository/io/jsonwebtoken/jjwt/0.12.3/jjwt-0.12.3.jar:~/.m2/repository/io/jsonwebtoken/jjwt-impl/0.11.2/jjwt-impl-0.11.2.jar:~/.m2/repository/io/jsonwebtoken/jjwt-api/0.11.2/jjwt-api-0.11.2.jar:~/.m2/repository/io/jsonwebtoken/jjwt-jackson/0.11.2/jjwt-jackson-0.11.2.jar:~/.m2/repository/com/nimbusds/nimbus-jose-jwt/9.10/nimbus-jose-jwt-9.10.jar:~/.m2/repository/com/fasterxml/jackson/core/jackson-core/2.13.0/jackson-core-2.13.0.jar:../../connector/target/connector-1.0.0.jar:../../sgx/target/sgx-1.0.0.jar:./ SgxSampleApp
```

> **Note:**
>
> - The proxy setting values for `HTTPS_PROXY_HOST` and `HTTPS_PROXY_PORT` have to be set by the user based on the system proxy settings.
> - The example above uses one such proxy settings and this can vary from system to system.
> - They can be set in [.env](../.env) by modifying the `HTTPS_PROXY_HOST` and `HTTPS_PROXY_PORT` variables accordingly.

### Output when example is run...
- When successful, the token and other information will be dispayed...


## Usage for running SGX Attestation Sample App as a docker container

The [SGX Attestation Sample App](SgxSampleApp.java) can be encapsulated as a container, enabling it to be executed in containerized environments.

### Prerequisites

Kindly adhere to the outlined steps below for installing both <b>Docker</b> and <b>docker-compose</b>—essential tools for running these applications within Docker containers.

Use <b>Docker version 20.10.17 or a more recent release</b>. Refer to the guide at https://www.digitalocean.com/community/tutorials/how-to-install-and-use-docker-on-ubuntu-20-04 for detailed instructions on Docker installation.

Use <b>docker-compose version 1.29.2 or a more recent release</b>. Follow the steps outlined at https://www.digitalocean.com/community/tutorials/how-to-install-and-use-docker-compose-on-ubuntu-20-04 for installing docker-compose.

Please ensure the necessary parameters required for the `SGX Attestation Sample App` being `TRUSTAUTHORITY_BASE_URL`, `TRUSTAUTHORITY_API_URL` and `TRUSTAUTHORITY_API_KEY` are present in [.env](../.env).
The required proxy settings values can be set in [sgx_sample_app.sh](sgx_sample_app.sh) by modifying the `-Dhttps.proxyHost` and `-Dhttps.proxyPort` variables accordingly.

### Build Instructions

Once `Docker` and `docker-compose` are installed, build the docker image with the following command:

```sh
docker-compose --env-file ../.env build
```

### Deployment Instructions

Run the `SGX Attestation Sample App` as docker container with the following command:

```sh
docker-compose --env-file ../.env up -d
```

Once the container is up and running, the logs for the same can be obtained by running below command:

```sh
docker logs -f trust-authority-java-client-sgx-sample-app
```

User can just re-run the container without having to build again if changing any parameters at runtime in [.env](../.env) with the following command:
```sh
docker-compose --env-file ../.env down && docker-compose --env-file ../.env up
```

### Deployment Instructions for using docker instead of docker-compose

In case one needs to use `docker` instead of `docker-compose` to run the container, once the image is built using the above `docker-compose build` command,
the `SGX Attestation Sample App` can be run using the following command from the `sgx-sample-app` directory:

```sh
docker run \
       --rm \
       --network host \
       --device=/dev/sgx_enclave \
       --device=/dev/sgx_provision \
       --env-file ../.env \
       -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket \
       -v /dev:/dev \
       trust-authority-java-client-sgx-sample-app:v1.0.0
```

> **Note:**
>
> - The proxy setting values for `HTTPS_PROXY_HOST` and `HTTPS_PROXY_PORT` have to be set by the user based on the system proxy settings.
> - The example above uses one such proxy settings and this can vary from system to system.
> - They can be set in [.env](../.env) by modifying the `HTTPS_PROXY_HOST` and `HTTPS_PROXY_PORT` variables accordingly.

### Output when example is run...
- When successful, the token and other information will be dispayed...
