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

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
