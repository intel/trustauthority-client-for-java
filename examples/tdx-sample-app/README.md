# TDX Attestation Sample App
The TDX Attestation Sample App is a Java application that uses the Intel Trust Authority Attestation Java Client libraries
to fetch token from Intel Trust Authority. The application is supposed to be run inside a TD. When run,
it collects a quote from the TD and sends it to Intel Trust Authority to retrieve a token.

```
┌────────────────────────────────────────────────┐
│    ┌──────────────────────────────────────┐    │
│    │          Docker Container            │    │
│    │                                      │    │
│    │    ┌──────────────────────────┐      │    │
│    │    │TDX Attestation Sample App│      │    │                ┌────────────────┐
│    │    └──────────────────────────┘      │    │                │                │
│    │                                      │    │                │                │
│    │    ┌──────────────────────────┐      │◄───┼───────────────►│   INTEL TRUST  │
│    │    │   connector-1.0.0.jar    │      │    │                │   AUTHORITY    │
│    │    └──────────────────────────┘      │    │                │   CLIENT       │
│    │                                      │    │                └────────────────┘
│    │    ┌──────────────────────────┐      │    │
│    │    │      tdx-1.0.0.jar       |      |    |
│    │    └──────────────────────────┘      │    │
│    │                                      │    │
│    └──────────────────────────────────────┘    │
│                                                │
│                  TD VM                         │
└────────────────────────────────────────────────┘
```
The diagram above depicts the components used in the TDX Attestation Sample App while running within
a docker container. The TDX Attestation Sample App example can also be run directly inside a TD vm (provided
the appropriate dependencies like DCAP have been installed).


## Usage for running TDX Attestation Sample App

### Compile the latest version of `connector` and `sgx` with the following command:

```sh
cd ../../ && \
mvn -X -e clean compile install package && \
cd -
```

### Compile the Sample App with the following command:

```sh
javac -cp ../../connector/target/connector-1.0.0.jar:../../tdx/target/tdx-1.0.0.jar:../../tdx/target/libs/* TdxSampleApp.java
```

### Run the Sample App with the following command:

Please ensure to set these variables in the environment as a pre-requisite:

```sh
export HTTPS_PROXY_HOST=<HTTPS_PROXY_HOST>
export HTTPS_PROXY_PORT=<HTTPS_PROXY_PORT>
export TRUSTAUTHORITY_BASE_URL=<TRUSTAUTHORITY_BASE_URL>
export TRUSTAUTHORITY_API_URL=<TRUSTAUTHORITY_API_URL>
export TRUSTAUTHORITY_API_KEY=<TRUSTAUTHORITY_API_KEY>
export TRUSTAUTHORITY_REQUEST_ID=<TRUSTAUTHORITY_REQUEST_ID>
export TRUSTAUTHORITY_POLICY_ID=<TRUSTAUTHORITY_POLICY_ID>
export RETRY_MAX=<MAX_NUMBER_OF_RETRIES>
export RETRY_WAIT_TIME=<MAX_RETRY_WAIT_TIME>
export LOG_LEVEL=<LOG_LEVEL>
```

Run the Sample App after setting the environment variables with the following command:

```sh
java -cp ../../connector/target/connector-1.0.0.jar:../../tdx/target/tdx-1.0.0.jar:../../tdx/target/libs/*:./ TdxSampleApp
```

> **Note:**
>
> - The proxy setting values for `HTTPS_PROXY_HOST` and `HTTPS_PROXY_PORT` have to be set by the user based on the system proxy settings.
> - The example above uses one such proxy settings and this can vary from system to system.
> - They can be set in [.env](../.env) by modifying the `HTTPS_PROXY_HOST` and `HTTPS_PROXY_PORT` variables accordingly.

### Output when example is run...
- When successful, the token and other information will be dispayed...


## Usage for running TDX Attestation Sample App as a docker container

The [TDX Attestation Sample App](TdxSampleApp.java) can be encapsulated as a container, enabling it to be executed in containerized environments.

### Prerequisites

Kindly adhere to the outlined steps below for installing both <b>Docker</b> and <b>docker-compose</b>—essential tools for running these applications within Docker containers.

Use <b>Docker version 20.10.17 or a more recent release</b>. Refer to the guide at https://docs.docker.com/engine/install/ubuntu/ for detailed instructions on Docker installation.

Use <b>docker-compose version 1.29.2 or a more recent release</b>. Follow the steps outlined at https://docs.docker.com/compose/install/linux/#install-the-plugin-manually for installing docker-compose.

Please ensure the necessary parameters required for the `TDX Attestation Sample App` being `TRUSTAUTHORITY_BASE_URL`, `TRUSTAUTHORITY_API_URL` and `TRUSTAUTHORITY_API_KEY` are present in [.env](../.env).
The required proxy settings values can be set in [sgx_sample_app.sh](sgx_sample_app.sh) by modifying the `-Dhttps.proxyHost` and `-Dhttps.proxyPort` variables accordingly.

### Build Instructions

Once `Docker` and `docker-compose` are installed, build the docker image with the following command:

```sh
docker-compose --env-file ../.env build
```

### Deployment Instructions

Once the image is built using the above `docker-compose build` command,
the `TDX Attestation Sample App` can be run using the following commands:

```sh
# Creating tdx_token.env file
cat <<EOF | tee tdx_token.env
HTTPS_PROXY_HOST=<https-proxy-host>
HTTPS_PROXY_PORT=<https-proxy-port>
TRUSTAUTHORITY_BASE_URL=<trustauthority-base-url>
TRUSTAUTHORITY_API_URL=<trustauthority-api-url>
TRUSTAUTHORITY_API_KEY=<trustauthority-api-key>
TRUSTAUTHORITY_REQUEST_ID=<trustauthority-request-id>
TRUSTAUTHORITY_POLICY_ID=<trustauthority-policy-id>
RETRY_MAX=<max-number-of-retries>
RETRY_WAIT_TIME=<max-retry-wait-time>
LOG_LEVEL=<log-level>
EOF

# Use docker to run the TDX Sample App...
docker run \
       --rm \
       --network host \
       --device=/dev/tdx_guest \
       --env-file tdx_token.env \
       trust-authority-java-client-tdx-sample-app:v1.0.0
```

> **Note:**
>
> - The proxy setting values for `HTTPS_PROXY_HOST` and `HTTPS_PROXY_PORT` have to be set by the user based on the system proxy settings.
> - The example above uses one such proxy settings and this can vary from system to system.
> - They can be set in [.env](../.env) by modifying the `HTTPS_PROXY_HOST` and `HTTPS_PROXY_PORT` variables accordingly.

### Output when example is run...
- When successful, the token and other information will be dispayed...
