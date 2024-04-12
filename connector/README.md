# Intel® Trust Authority Java Client Connector

`com.intel.trustauthority.connector`

The Intel Trust Authority Connector for Java allows confidential computing clients and relying parties to consume Intel Trust Authority remote attestation services. The Connector enables clients to request a nonce or attestation token, verify an attestation token, and download the JWKS of certificates used to sign nonces and tokens. The Connector communicates with Intel Trust Authority by using the attestation REST API. Relying parties can use the Connector by itself, and attesters can use the Connector and one of the TEE adapters to collect evidence for a quote. 

For more information, see [Java Client Integration](https://docs.trustauthority.intel.com/main/articles/integrate-java-client.html) in the Intel Trust Authority documentation.

## System Requirement

- Ubuntu 20.04
- OpenJDK version 17.0.8.1 or newer — The latest open-source version of the Java JDK is avaiable at [https://jdk.java.net/21/](https://jdk.java.net/21/).
- Apache Maven 3.6.3 or newer — To install Apache Maven, follow the instructions at https://www.baeldung.com/install-maven-on-windows-linux-mac. If the target system is behind a proxy server, you'll need to follow the steps for setting up a proxy for Maven at https://www.baeldung.com/maven-behind-proxy. 

The TEE adapters for Intel SGX and Intel TDX require Intel® SGX DCAP for quote generation. For more information, see [https://github.com/intel/SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives).

## Usage

Include the following in your pom.xml file:

```xml
<dependencies>
    <dependency>
        <groupId>com.intel.trustauthority</groupId>
        <artifactId>connector</artifactId>
        <version>1.0.0</version>
    </dependency>
</dependencies>
```

Import the Trust Authority Connector package:

```java
import com.intel.trustauthority.connector.*
```

### To create a new Connector instance

```java
import com.intel.trustauthority.connector.Config;
import com.intel.trustauthority.connector.TrustAuthorityConnector;

// Initialize config required for connector using trustAuthorityBaseUrl (https://portal.trustauthority.intel.com),
// trustAuthorityApiUrl (https://api.trustauthority.intel.com), trustAuthorityApiKey, and retryConfig.
Config cfg = new Config(trustAuthorityBaseUrl, trustAuthorityApiUrl, trustAuthorityApiKey, retryConfig);

// Initialize TrustAuthorityConnector with the config
TrustAuthorityConnector connector = new TrustAuthorityConnector(cfg);
```

### To attest a TEE with Intel Trust Authority

To create a TEE adapter,  refer to the [Intel SGX adapter](../sgx/README.md) or [Intel TDX adapter](../tdx/README.md) README files.

```java
// Initialize AttestArgs required for attestation
AttestArgs attestArgs = new AttestArgs(adapter, policyIDs, requestID, tokenSigningAlg, policyMustMatch);

// Invoke the attest API of the connector
AttestResponse response = connector.attest(attestArgs);

// Verify the received token
JWTClaimsSet claims = connector.verifyToken(response.getToken());
```

The `attest()` method is the simplest method for an attesting client application to request an attestation token from Intel Trust Authority. The `attest()` method gets a nonce, invokes the Intel TDX adapter to collect evidence, and then sends the evidence and an optional Request ID to Intel Trust Authority for verification. If successful, `attest()` returns an attestation token and HTTP response headers.

The `verifyToken()` method checks to see that the attestation token is properly formated and signed with a valid Intel Trust Authority JWK certificate. It does not check the claims or data contained in the JWT body.


## Unit Tests

See the main [README](../README.md) for instructions for unit tests.

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
