# Intel® Trust Authority Connector
Java module for communicating with Intel Trust Authority via REST APIs.

## Java Requirement

Use <b>openjdk version "17.0.8.1" or newer</b>. Follow https://www.java.com/en/download/manual.jsp for installation of Java.

## Maven Requirement

Use <b>Apache Maven 3.6.3 or newer</b>. Follow https://www.baeldung.com/install-maven-on-windows-linux-mac for installation of Maven.

If you are running behind a proxy, follow https://www.baeldung.com/maven-behind-proxy for setting up proxy for Maven.

## Install

Install the latest version of the module with the following command from the `TrustAuthority` directory:

```sh
mvn -X -e clean compile install package
```

## Unit Tests

To run the tests, run the following command:

```sh
mvn -X -e test
```

See the example test in `test/java/trust_authority_client/ConnectorTest.java` for an example of a test.

## Usage for running SgxSampleApp and TdxSampleApp

The [SgxSampleApp](./src/main/java/trust_authority_client/SgxSampleApp.java) and [TdxSampleApp](./src/main/java/trust_authority_client/TdxSampleApp.java) are sample applications to fetch and verify an SGX/TDX quote from an SGX/TDX enabled platform respectively.

Compile the latest version of `SgxSampleApp` and `TdxSampleApp` with the following command from the `TrustAuthority` directory:

```sh
mvn -X -e clean compile install package
```

Run the `SgxSampleApp`:

Since the `SgxSampleApp` requires an enclave to be initialized, run this step to generate a signed enclave:

```sh
cd src/main/java/trust_authority_client/sgx-example-enclave/enclave/ && \
make && \
cd -
```

Once the above step is complete and the `enclave.signed.so` file is generated, run the below command to run the `SgxSampleApp` to fetch the SGX quote:

```sh
java -Dhttps.proxyHost=proxy-fm.intel.com -Dhttps.proxyPort=911 -cp ~/.m2/repository/org/bouncycastle/bcprov-jdk15on/1.68/bcprov-jdk15on-1.68.jar:~/.m2/repository/com/fasterxml/jackson/core/jackson-annotations/2.13.0/jackson-annotations-2.13.0.jar:~/.m2/repository/com/fasterxml/jackson/core/jackson-databind/2.13.0/jackson-databind-2.13.0.jar:~/.m2/repository/com/fasterxml/jackson/core/jackson-core/2.13.0/jackson-core-2.13.0.jar:~/.m2/repository/net/java/dev/jna/jna/5.9.0/jna-5.9.0.jar:~/.m2/repository/com/google/code/gson/gson/2.9.0/gson-2.9.0.jar:~/.m2/repository/io/jsonwebtoken/jjwt/0.12.3/jjwt-0.12.3.jar:target/trust-authority-client-java-1.0.0.jar:~/.m2/repository/io/jsonwebtoken/jjwt-impl/0.11.2/jjwt-impl-0.11.2.jar:~/.m2/repository/io/jsonwebtoken/jjwt-api/0.11.2/jjwt-api-0.11.2.jar:~/.m2/repository/io/jsonwebtoken/jjwt-jackson/0.11.2/jjwt-jackson-0.11.2.jar:~/.m2/repository/com/nimbusds/nimbus-jose-jwt/9.10/nimbus-jose-jwt-9.10.jar:~/.m2/repository/com/fasterxml/jackson/core/jackson-core/2.13.0/jackson-core-2.13.0.jar trust_authority_client.SgxSampleApp
```

## Note

The proxy setting values for `https.proxyHost` and `https.proxyPort` have to be set by the user based on the system proxy settings.
The example above uses one such proxy settings and this can vary from system to system, has to be set accordingly.

Run the `TdxSampleApp` with the following command:

```sh
java -Dhttps.proxyHost=proxy-fm.intel.com -Dhttps.proxyPort=911 -cp ~/.m2/repository/org/bouncycastle/bcprov-jdk15on/1.68/bcprov-jdk15on-1.68.jar:~/.m2/repository/com/fasterxml/jackson/core/jackson-annotations/2.13.0/jackson-annotations-2.13.0.jar:~/.m2/repository/com/fasterxml/jackson/core/jackson-databind/2.13.0/jackson-databind-2.13.0.jar:~/.m2/repository/com/fasterxml/jackson/core/jackson-core/2.13.0/jackson-core-2.13.0.jar:~/.m2/repository/net/java/dev/jna/jna/5.9.0/jna-5.9.0.jar:~/.m2/repository/com/google/code/gson/gson/2.9.0/gson-2.9.0.jar:~/.m2/repository/io/jsonwebtoken/jjwt/0.12.3/jjwt-0.12.3.jar:target/trust-authority-client-java-1.0.0.jar:~/.m2/repository/io/jsonwebtoken/jjwt-impl/0.11.2/jjwt-impl-0.11.2.jar:~/.m2/repository/io/jsonwebtoken/jjwt-api/0.11.2/jjwt-api-0.11.2.jar:~/.m2/repository/io/jsonwebtoken/jjwt-jackson/0.11.2/jjwt-jackson-0.11.2.jar:~/.m2/repository/com/nimbusds/nimbus-jose-jwt/9.10/nimbus-jose-jwt-9.10.jar:~/.m2/repository/com/fasterxml/jackson/core/jackson-core/2.13.0/jackson-core-2.13.0.jar trust_authority_client.TdxSampleApp
```

## Note

The proxy setting values for `https.proxyHost` and `https.proxyPort` have to be set by the user based on the system proxy settings.
The example above uses one such proxy settings and this can vary from system to system, has to be set accordingly.

## Usage for running SampleApps as a docker container

The [SampleApp](./src/main/java/trust_authority_client/SampleApp.java) and [SampleAppServer](./src/main/java/trust_authority_client/SampleAppServer.java) are encapsulated in containers, enabling them to be executed in containerized environments.

Kindly adhere to the outlined steps below for installing both <b>Docker</b> and <b>docker-compose</b>—essential tools for running these applications within Docker containers.

Use <b>Docker version 20.10.17 or a more recent release</b>. Refer to the guide at https://www.digitalocean.com/community/tutorials/how-to-install-and-use-docker-on-ubuntu-20-04 for detailed instructions on Docker installation.

Use <b>docker-compose version 1.29.2 or a more recent release</b>. Follow the steps outlined at https://www.digitalocean.com/community/tutorials/how-to-install-and-use-docker-compose-on-ubuntu-20-04 for installing docker-compose.


Once `Docker` and `docker-compose` are installed, build the docker image with the following command:

```sh
docker-compose build
```

Run the `SampleApp` as a docker container with the following command:

```sh
docker-compose up
```

The arguments for the `SampleApp` being `TRUSTAUTHORITY_BASE_URL`, `TRUSTAUTHORITY_API_URL` and `TRUSTAUTHORITY_API_KEY` can be changed at runtime if required by modifying the respective key-value pairs at [.env](.env).

User can just re-run the container without having to build again if changing any parameters at runtime in [.env](.env) with the following command:
```sh
docker-compose down && docker-compose up
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
