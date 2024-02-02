# Intel® Trust Authority Java Client SGX Adapter

`com.intel.trustauthority.sgx`

The Intel Trust Authority adapter for Intel SGX clients allows a confidential computing client (the attester) written in Java to collect a quote from an Intel SGX enclave for verification/attestation by Intel Trust Authority. This package allows applications written in Java to leverage Intel SGX DCAP. The Intel SGX adapter imports the [Intel Trust Authority Java Connector](../connector/README.md) (`com.intel.trustauthority.connector`). 

For more information, see [Java Client Integration](https://docs.trustauthority.intel.com/main/articles/integrate-java-client.html) in the Intel Trust Authority documentation.
 
## System Requirements

- Ubuntu 20.04
- Intel® SGX DCAP for quote generation. For more information, see [https://github.com/intel/SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives)
- OpenJDK version "17.0.8.1" or newer — The latest open-source version of the Java JDK is avaiable at [https://jdk.java.net/21/](https://jdk.java.net/21/).
- Apache Maven 3.6.3 or newer — To install Apache Maven, follow the instructions at https://www.baeldung.com/install-maven-on-windows-linux-mac. If the target system is behind a proxy server, you'll need to follow the steps for setting up a proxy for Maven at https://www.baeldung.com/maven-behind-proxy. 

## Usage

The following code fragment is from the [Intel SGX sample application](../examples/sgx-sample-app/README.md). This fragment creates a new Intel SGX adapter, and then uses the adapter to collect a quote from an enclave. The Intel SGX enclave must expose a method for creating an enclave report and use a SHA256 hash value as reportdata.

```java
import com.intel.trustauthority.sgx.SgxAdapter;
import com.intel.trustauthority.connector.Evidence;

// Create the SgxAdapter object
SgxAdapter sgxAdapter = new SgxAdapter(enclaveId[0], userData, EnclaveLibrary.EnclaveFunction);

// Get the Intel Sgx evidence (quote)
Evidence evidence = sgxAdapter.collectEvidence(nonce);
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
