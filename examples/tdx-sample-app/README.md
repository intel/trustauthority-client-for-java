# TDX Attestation Sample App

The Intel TDX attestation sample app is a Java application that uses the Intel Trust Authority Attestation Java Client packages
to get an attestation token from Intel Trust Authority. The application runs inside an Intel TDX trust domain (TD). When run,
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
│    │    └──────────────────────────┘      │    │                │   SERVER       │
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
The diagram above depicts the components used in the Intel TDX attestation sample app while running within
a Docker container. The example can also be run directly inside a TD vm (provided
the appropriate dependencies like Intel SGX DCAP have been installed).

## Usage for running the Intel TDX sample app in a Docker container

The [Intel TDX Attestation Sample App](src/main/java/com/intel/trustauthority/tdx/SampleApp.java) can be encapsulated as a container, enabling it to be executed in containerized environments.

### Prerequisites

Follow the steps below for installing both **docker** and **docker-compose**. They are essential tools for running these applications within Docker containers.

1. Use Docker version 20.10.17 or later. Refer to the guide at https://docs.docker.com/engine/install/ubuntu/ for detailed instructions on Docker installation.

2. Use docker-compose version 1.29.2 or later. Follow the steps outlined at https://docs.docker.com/compose/install/linux/#install-the-plugin-manually for installing docker-compose.

3. Update `MAVEN_PROXY_HOST` and `MAVEN_PROXY_PORT` if running behind a proxy in [.env](../.env).

### Build Instructions

1. After  `Docker` and `docker-compose` are installed, build the Docker image with the following command:
   ```sh
   docker-compose --env-file ../.env build
   ```

2. After the image is built using the  `docker-compose build` command, the `TDX Attestation Sample App` can be run using the following commands.

   ```sh
   # Creating tdx_token.env file
       cat <<EOF | tee tdx_token.env
       HTTPS_PROXY_HOST=<https-proxy-host>
       HTTPS_PROXY_PORT=<https-proxy-port>
       TRUSTAUTHORITY_BASE_URL="https://portal.trustauthority.intel.com"
       TRUSTAUTHORITY_API_URL="https://api.trustauthority.intel.com"
       TRUSTAUTHORITY_API_KEY=<trustauthority-api-key>
       TRUSTAUTHORITY_REQUEST_ID=<trustauthority-request-id>
       TRUSTAUTHORITY_POLICY_ID=<trustauthority-policy-id>
       TOKEN_SIGNING_ALG=<token-signing-alg>
       RETRY_MAX=<max-number-of-retries>
       RETRY_WAIT_TIME=<max-retry-wait-time>
       LOG_LEVEL=<log-level>
       EOF
     
   # Make sure the Intel(R) TDX driver device is set with the following permissions:
   #    crw-rw---- root <user-group> /dev/tdx_guest
       
   # Use docker to run the TDX Sample App...
   docker run \
       --rm \
       --network host \
       --device=/dev/tdx_guest \
       --env-file tdx_token.env \
       --group-add $(getent group <user-group> | cut -d: -f3) \
       trust-authority-java-client-tdx-sample-app:v1.0.0
   ```

> [!NOTE]
> - The proxy setting values for `HTTPS_PROXY_HOST` and `HTTPS_PROXY_PORT` have to be set by the user based on the system proxy settings.
> - The example above uses one such proxy settings and this can vary from system to system.

If the sample app is successful, it will display the token and other information. 

## Usage for running the Intel TDX attestation sample app as a native application

1.  Compile the latest version of `connector` and `tdx` with the following command.

   ```sh
   cd ../../ && \
   mvn -X -e clean compile install package -DskipTests && \
   cd -
   ```

2.  Compile the Sample App with the following command.

   ```sh
   mvn compile
   ```

3. You must set these variables in the environment before running the sample app.

   ```sh
   export HTTPS_PROXY_HOST=<HTTPS_PROXY_HOST>
   export HTTPS_PROXY_PORT=<HTTPS_PROXY_PORT>
   export TRUSTAUTHORITY_BASE_URL=<TRUSTAUTHORITY_BASE_URL>
   export TRUSTAUTHORITY_API_URL=<TRUSTAUTHORITY_API_URL>
   export TRUSTAUTHORITY_API_KEY=<TRUSTAUTHORITY_API_KEY>
   export TRUSTAUTHORITY_REQUEST_ID=<TRUSTAUTHORITY_REQUEST_ID>
   export TRUSTAUTHORITY_POLICY_ID=<TRUSTAUTHORITY_POLICY_ID>
   export TOKEN_SIGNING_ALG=<TOKEN_SIGNING_ALG>
   export RETRY_MAX=<MAX_NUMBER_OF_RETRIES>
   export RETRY_WAIT_TIME=<MAX_RETRY_WAIT_TIME>
   export LOG_LEVEL=<LOG_LEVEL>
   ```

4. After setting the environment variables, run the sample app with the following command.

   ```sh
   mvn exec:java -Dexec.mainClass="com.intel.trustauthority.tdxsampleapp.SampleApp"
   ```

> [!NOTE]
> - The proxy setting values for `HTTPS_PROXY_HOST` and `HTTPS_PROXY_PORT` have to be set by the user based on the system proxy settings.
> - The example above uses one such proxy settings and this can vary from system to system.

