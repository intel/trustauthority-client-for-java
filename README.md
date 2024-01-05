# Intel® Trust Authority Java Client
Intel Trust Authority Client provides a set of Java packages for attesting different TEEs with Intel Trust Authority. Users can import the Java packages within their application and make REST calls to Intel Trust Authority for fetching token containing information about the TEE attested that can be verified.

## System Requirement

Use <b>Ubuntu 20.04</b>.

Use <b>openjdk version "17.0.8.1" or newer</b>. Follow https://www.java.com/en/download/manual.jsp for installation of Java.

Use <b>Apache Maven 3.6.3 or newer</b>. Follow https://www.baeldung.com/install-maven-on-windows-linux-mac for installation of Maven.

If you are running behind a proxy, follow https://www.baeldung.com/maven-behind-proxy for setting up proxy for Maven.

## Installation

Install the latest version of the module with the following command:

```sh
mvn -X -e clean compile install package
```

## Unit Tests

The unit tests can be found at [TrustAuthorityConnectorTest.java](./connector/src/test/java/com/intel/trustauthority/connector/TrustAuthorityConnectorTest.java), and they can be executed using Maven by running the command:

```sh
mvn test
```

### For E2E token collection and signature verification samples, refer
SGX: [SGX Sample App](./examples/sgx-sample-app/README.md)
TDX: [TDX Sample App](./examples/tdx-sample-app/README.md)

## License

This source is distributed under the BSD-style license found in the [LICENSE](LICENSE)
file.
