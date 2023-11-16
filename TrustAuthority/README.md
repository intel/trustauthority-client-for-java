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

## Usage

Refer the [SampleApp](./src/main/java/trust_authority_client/SampleApp.java), an application testing all the APIs of the Java connector.

The [SampleApp](./src/main/java/trust_authority_client/SampleApp.java) demonstrates how to use the Trust Authority Java Client from an external third party application perspective.

The [SampleAppServer](./src/main/java/trust_authority_client/SampleAppServer.java) mimics the functionalities of Amber Server serving the required tokens, certs etc with its
respective REST API calls.

Run the `SampleAppServer` with the following command in a new terminal:

```sh
java -cp target/trust-authority-client-java-1.0.0.jar trust_authority_client.SampleAppServer
```

Run the `SampleApp` with the following command:

```sh
java -cp ~/.m2/repository/com/google/code/gson/gson/2.9.0/gson-2.9.0.jar:~/.m2/repository/io/jsonwebtoken/jjwt/0.12.3/jjwt-0.12.3.jar:target/trust-authority-client-java-1.0.0.jar:~/.m2/repository/io/jsonwebtoken/jjwt-impl/0.11.2/jjwt-impl-0.11.2.jar:~/.m2/repository/io/jsonwebtoken/jjwt-api/0.11.2/jjwt-api-0.11.2.jar:~/.m2/repository/io/jsonwebtoken/jjwt-jackson/0.11.2/jjwt-jackson-0.11.2.jar:~/.m2/repository/com/nimbusds/nimbus-jose-jwt/9.4/nimbus-jose-jwt-9.4.jar trust_authority_client.SampleApp
```

## Usage for running SampleApp as a docker container

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

The arguments for the `SampleApp` being `BASE_URL`, `API_URL` and `API_KEY` can be changed at runtime if required by modifying the respective key-value pairs at [.env](.env).

User can just re-run the container without having to build again if changing any parameters at runtime in [.env](.env) with the following command:
```sh
docker-compose down && docker-compose up
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.