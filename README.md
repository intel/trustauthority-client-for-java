# Intel® Trust Authority Java Client

The Intel Trust Authority client for Java is a collection of packages that provide attestation services for both attesters and relying parties. 

- [Connector](./connector/README.md) `com.intel.trustauthority.connector` — The Connector handles communication with Intel Trust Authority via REST APIs. The Connector provides methods to get a nonce, request an attestation token, verify an attestation token, and get a copy of the JWK signing certificates used to sign tokens. Relying parties can use the Connector without installing a TEE adapter or Intel SGX DCAP.
- [Intel SGX Adapter](./sgx/README.md) `com.intel.trustauthority.sgx` — The Intel SGX adapter uses Intel SGX DCAP to collect evidence from an Intel SGX enclave.
- [Intel TDX Adapter](./tdx/README.md) `com.intel.trustauthority.tdx` — The Intel TDX adapter uses Intel SGX DCAP to collect evidence from an Intel TDX TD.

For more information, see [Java Client Integration](https://docs.trustauthority.intel.com/main/articles/integrate-java-client.html) in the Intel Trust Authority documentation. 

## System requirements

- Ubuntu 20.04
- OpenJDK version 17.0.8.1 or newer — The latest open-source version of the Java JDK is available at [https://jdk.java.net/21/](https://jdk.java.net/21/).
- Apache Maven 3.6.3 or newer — To install Apache Maven, follow the instructions at https://www.baeldung.com/install-maven-on-windows-linux-mac. If the target system is behind a proxy server, you'll need to follow the steps for setting up a proxy for Maven at https://www.baeldung.com/maven-behind-proxy. 

The TEE adapters for Intel SGX and Intel TDX require Intel® SGX DCAP for quote generation. For more information, see [https://github.com/intel/SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives). Relying parties that use the Connector don't need Intel SGX DCAP.

## Installation

Install the latest version of the Java client for Intel Trust Authority with the following command:

```sh
mvn -X -e clean compile install package
```

## Usage

For more information, see [Java Client Integration](https://docs.trustauthority.intel.com/main/articles/integrate-java-client.html) in the Intel Trust Authority documentation. For example applications with token collection and signature verification samples, refer to:

- Intel SGX: [SGX Sample App](./examples/sgx-sample-app/README.md)

- Intel TDX: [TDX Sample App](./examples/tdx-sample-app/README.md)

### Create a connector instance

```java
import com.intel.trustauthority.connector.Config;
import com.intel.trustauthority.connector.TrustAuthorityConnector;

// Initialize config required for connector using trustAuthorityBaseUrl (https://portal.trustauthority.intel.com), trustAuthorityApiUrl (https://api.truastauthority.intel.com), trustAuthorityApiKey, and retryConfig
Config cfg = new Config(trustAuthorityBaseUrl, trustAuthorityApiUrl, trustAuthorityApiKey, retryConfig);

// Initialize TrustAuthorityConnector with the config
TrustAuthorityConnector connector = new TrustAuthorityConnector(cfg);
```

### To attest with Intel Trust Authority using a TEE Adapter

```java
// Initialize AttestArgs required for attestation
AttestArgs attestArgs = new AttestArgs(adapter, policyIDs, requestID);

// Invoke the attest API of the connector
AttestResponse response = connector.attest(attestArgs);

// Verify the received token
JWTClaimsSet claims = connector.verifyToken(response.getToken());
```

### To get an Intel Trust Authority signed nonce

```java
GetNonceResponse nonceResponse = GetNonce(new GetNonceArgs(args.getRequestId()));
if (nonceResponse == null) {
    throw new Exception("Unable to collect a nonce from Intel Trust Authority");
}
```

The nonceResponse class contains the nonce and the HTTP response headers.

### To verify an Intel Trust Authority signed token

```java
AttestResponse response = connector.attest(attestArgs);
...
JWTClaimsSet claims = connector.verifyToken(response.getToken());
```
The `verifyToken()` method checks to see that the attestation token is properly formated and signed with a valid Intel Trust Authority JWK certificate. It does not check the claims or data contained in the JWT body. If successful, `verifyToken()` returns a parsed attestation token in JSON format. 

## Unit Tests

The unit tests can be found at [TrustAuthorityConnectorTest.java](./connector/src/test/java/com/intel/trustauthority/connector/TrustAuthorityConnectorTest.java), and they can be executed using Maven by running the command:

```sh
mvn test
```

### Running unit tests coverage tool

The JaCoCo plugin is integrated to check the code coverage for the project at [pom.xml](./pom.xml#L41). The code test coverage percentage can be checked by running the following commands from the connector directory:

```sh
# Run unit tests to generate the test report.
mvn test

# Command to print the percentage code coverage in the console.
awk -F, '{
    instructions += $4 + $5;
    covered += $5
} 
END {
    print covered, "/", instructions, " instructions covered";
    print 100 * covered / instructions, "% covered"
}' target/site/jacoco/jacoco.csv
```

An HTML-based report is generated and can be opened using a web browser to view the code coverage details. The [index.html](target/site/jacoco/index.html) for the site can be found at `target/site/jacoco/index.html` once the above commands are run.


## License

This source is distributed under the BSD-style license found in the [LICENSE](LICENSE)
file.
