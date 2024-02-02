# Intel® Trust Authority Java Client for Intel TDX

`com.intel.trustauthority.tdx`

The Intel Trust Authority adapter for Intel TDX clients allows a confidential computing client (the attester) written in Java to collect a quote from an Intel TDX trust domain (TD), which is forwarded to Intel Trust Authority for verification/attestation. This adapter allows applications written in Java to leverage Intel SGX DCAP. The Intel TDX adapter imports the [Intel Trust Authority Java Connector](../connector/README.md) (`com.intel.trustauthority.connector`). 

The Intel TDX adapter takes care of calling the Intel DCAP functions, generating a TDREPORT, and formatting a quote for attestation (verification) by Intel Trust Authority. Optionally, an attester can include userData with the evidence collected from Intel SGX DCAP, and then a SHA512 hash of the nonce + original user data (if any) is output in the attestation token. The original userData output to the attestation token is limited to 64 bytes, and it's commonly used to pass an encryption key or a hash to the relying party.

For more information, see [Java Client Integration](https://docs.trustauthority.intel.com/main/articles/integrate-java-client.html) in the Intel Trust Authority documentation.

## System Requirements

- Ubuntu 20.04
- Intel® SGX DCAP for quote generation. For more information, see [https://github.com/intel/SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives)
- OpenJDK version "17.0.8.1" or newer — The latest open-source version of the Java JDK is avaiable at [https://jdk.java.net/21/](https://jdk.java.net/21/).
- Apache Maven 3.6.3 or newer — To install Apache Maven, follow the instructions at https://www.baeldung.com/install-maven-on-windows-linux-mac. If the target system is behind a proxy server, you'll need to follow the steps for setting up a proxy for Maven at https://www.baeldung.com/maven-behind-proxy. 

## Usage

The Intel TDX adapter has two main functions:

- TdxAdapter() — Instantiates a new TDX adapter.
- collectEvidence() — Invokes Intel SGX DCAP and event log parser to collect evidence for a quote from the TD.

 The following code fragments are from the [Intel TDX example application](../examples/tdx-sample-app/). 
```java
import com.intel.trustauthority.tdx.TdxAdapter;
import com.intel.trustauthority.connector.Evidence;

// Create the TdxAdapter object
TdxAdapter tdxAdapter = new TdxAdapter(userData);

// Collect the Tdx quote
Evidence evidence = tdxAdapter.collectEvidence(nonce);
```
## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
 