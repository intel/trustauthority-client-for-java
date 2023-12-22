# Intel® Trust Authority Java Client Connector
Java library for communicating with Intel Trust Authority via REST APIs.

## System Requirement

Use <b>Ubuntu 20.04</b>. 

Use <b>openjdk version "17.0.8.1" or newer</b>. Follow https://www.java.com/en/download/manual.jsp for installation of Java.

Use <b>Apache Maven 3.6.3 or newer</b>. Follow https://www.baeldung.com/install-maven-on-windows-linux-mac for installation of Maven.

If you are running behind a proxy, follow https://www.baeldung.com/maven-behind-proxy for setting up proxy for Maven.

## Usage

Create a new Connector instance, then use the exposed interfaces to
access different parts of the Intel Trust Authority API.

```java
import com.intel.trustauthority.connector.Config;
import com.intel.trustauthority.connector.TrustAuthorityConnector;

// Initialize config required for connector using trustauthority_base_url, trustauthority_api_url and trustauthority_api_key
Config cfg = new Config(trustauthority_base_url, trustauthority_api_url, trustauthority_api_key);

// Initialize TrustAuthorityConnector with the config
TrustAuthorityConnector connector = new TrustAuthorityConnector(cfg);
```

### To attest and verify TEE with Intel Trust Authority using TEE Adapter
To create adapter refer [sgx](../sgx/README.md) or [tdx](../tdx/README.md):

```java
// Initialize AttestArgs required for attestation
AttestArgs attestArgs = new AttestArgs(adapter, policyIDs, requestID);

// Invoke the attest API of the connector
AttestResponse response = connector.attest(attestArgs);

// Verify the received token
JWTClaimsSet claims = connector.verifyToken(response.getToken());
```

## Unit Tests

The unit tests can be found at [TrustAuthorityConnectorTest.java](./src/test/java/com/intel/trustauthority/connector/TrustAuthorityConnectorTest.java), and they can be executed using Maven by running the command:

```sh
mvn test
```

### Running unit tests coverage tool

JaCoCo (Java Code Coverage) is a widely used code coverage tool for Java applications.
It helps us to measure how much of the code is exercised by the test suite.

JaCoCo plugin is integrated to check the code coverage for the project at [pom.xml](./pom.xml#L41).
The code test coverage percentage can be checked by running the following commands from the connector directory:

```sh
# Run unit tests to generate the test report
mvn test

# Command to print the percentage code coverage in console
awk -F, '{
    instructions += $4 + $5;
    covered += $5
} 
END {
    print covered, "/", instructions, " instructions covered";
    print 100 * covered / instructions, "% covered"
}' target/site/jacoco/jacoco.csv
```

An HTML based report is also generated and can be opened using a web browser to view the code coverage details.
The [index.html](target/site/jacoco/index.html) for the same can be found at `target/site/jacoco/index.html` once the above commands are run.

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
