# SGX Attestation Sample App
The Intel SGX attestation sample app is a Java application that uses the Intel Trust Authority Attestation Java Client packages
to get an attestation token from Intel Trust Authority. The application contains an example SGX enclave. When run, 
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
│    │    └──────────────────────────┘      │    │                │   SERVER       |
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
The diagram above depicts the components used in the Intel SGX attestation sample app while running within
a Docker container. The Intel SGX sample app can also be run directly on an Intel SGX host, provided that dependencies such as Intel SGX DCAP have been installed. 


## Usage for running the Intel SGX Attestation Sample App as a Docker container

The [SGX Attestation Sample App](src/main/java/com/intel/trustauthority/sgx/SampleApp.java) can be encapsulated in a container, enabling it to be executed in containerized environments.

### Prerequisites

Follow the steps below for installing both **Docker** and **docker-compose**  — essential tools for running these applications within Docker containers.

1. Use **Docker** version 20.10.17 or later. Refer to the guide at https://docs.docker.com/engine/install/ubuntu/ for detailed instructions on Docker installation.

2. Use **docker-compose** version 1.29.2 or later. Follow the steps outlined at https://docs.docker.com/compose/install/linux/#install-the-plugin-manually for installing docker-compose.

3. Update `MAVEN_PROXY_HOST` and `MAVEN_PROXY_PORT` if running behind a proxy in [.env](../.env).


### Build Instructions

1. After `Docker` and `docker-compose` are installed, build the Docker image with the following command.
   ```sh
   docker-compose --env-file ../.env build
   ```

3. After the image is built using the above `docker-compose build` command, the `SGX Attestation Sample App` can be run using the following commands.

   ```sh
   # Creating the sgx_token.env file
   cat <<EOF | tee sgx_token.env
   HTTPS_PROXY_HOST=<https-proxy-host>
   HTTPS_PROXY_PORT=<https-proxy-port>
   TRUSTAUTHORITY_BASE_URL="https://portal.trustauthority.intel.com"
   TRUSTAUTHORITY_API_URL="https://api.trustauthority.intel.com"
   TRUSTAUTHORITY_API_KEY=<trustauthority-attestation-api-key>
   TRUSTAUTHORITY_REQUEST_ID=<trustauthority-request-id>
   TRUSTAUTHORITY_POLICY_ID=<trustauthority-policy-id>
   TOKEN_SIGNING_ALG=<token-signing-alg>
   RETRY_MAX=<max-number-of-retries>
   RETRY_WAIT_TIME=<max-retry-wait-time>
   LOG_LEVEL=<log-level>
   SGX_AESM_ADDR=1
   EOF
       
   # Use docker to run the Intel SGX sample app
   docker run \
          --rm \
          --network host \
          --device=/dev/sgx_enclave \
          --device=/dev/sgx_provision \
          --env-file sgx_token.env \
          -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket \
          -v /dev:/dev \
          --group-add $(getent group sgx_prv | cut -d: -f3) \
          trust-authority-java-client-sgx-sample-app:v1.0.0
   ```

> [!NOTE]
> - The proxy setting values for `HTTPS_PROXY_HOST` and `HTTPS_PROXY_PORT` have to be set by the user based on the system proxy settings.
> - The example above uses one such proxy settings and this can vary from system to system.

When successful, the token and other information will be displayed.

## Usage for running SGX Attestation Sample App as a native application

1. Compile the latest version of `connector` and `sgx` with the following command:

   ```sh
   cd ../../ && \
   mvn -X -e clean compile install package && \
   cd -
   ```

2. Since the SGX attestation sample app requires an enclave to be initialized, run this step to generate a signed enclave.

   ```sh
   cd enclave/ && \
   make && \
   cd -
   ```

3. Once the above step is complete and the `enclave.signed.so` file is generated, run the following command to compile the `SGX Attestation Sample App`.

   ```sh
   mvn compile
   ```

4. These variables must be set in the environment.

   ```sh
   export HTTPS_PROXY_HOST=<HTTPS_PROXY_HOST>
   export HTTPS_PROXY_PORT=<HTTPS_PROXY_PORT>
   export TRUSTAUTHORITY_BASE_URL="https://portal.trustauthority.intel.com"
   export TRUSTAUTHORITY_API_URL="https://api.trustauthority.intel.com"
   export TRUSTAUTHORITY_API_KEY=<TRUSTAUTHORITY_API_KEY>
   export TRUSTAUTHORITY_REQUEST_ID=<TRUSTAUTHORITY_REQUEST_ID>
   export TRUSTAUTHORITY_POLICY_ID=<TRUSTAUTHORITY_POLICY_ID>
   export TOKEN_SIGNING_ALG=<TOKEN_SIGNING_ALG>
   export RETRY_MAX=<MAX_NUMBER_OF_RETRIES>
   export RETRY_WAIT_TIME=<MAX_RETRY_WAIT_TIME>
   export LOG_LEVEL=<LOG_LEVEL>
   export SGX_AESM_ADDR=1
   ```

5. After setting the environment variables, run the sample app with the following command.

   ```sh
   mvn exec:java -Dexec.mainClass="com.intel.trustauthority.sgxsampleapp.SampleApp"
   ```

> [!NOTE]
> - The proxy setting values for `HTTPS_PROXY_HOST` and `HTTPS_PROXY_PORT` have to be set by the user based on the system proxy settings.
> - The example above uses one such proxy settings and this can vary from system to system.

