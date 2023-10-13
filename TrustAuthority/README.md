# Intel® Trust Authority Connector
Java module for communicating with Intel Trust Authority via REST APIs.

## Java Requirement

Use <b>openjdk version "19.0.2" or newer</b>. Follow https://www.java.com/en/download/manual.jsp for installation of Java.

## Maven Requirement

Use <b>Apache Maven 3.6.3 or newer</b>. Follow https://www.baeldung.com/install-maven-on-windows-linux-mac for installation of Maven.

If you are running behind a proxy, follow https://www.baeldung.com/maven-behind-proxy for setting up proxy for Maven.

## Install

Install the latest version of the module with the following command:

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

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.