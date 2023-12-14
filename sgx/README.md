# Intel® Trust Authority Java Client SGX Adapter
Java library for collecting SGX Quote from SGX enabled platform.

This library leverages Intel SGX DCAP for Quote generation: [https://github.com/intel/SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives)

## System Requirement

Use <b>Ubuntu 20.04</b>. 

Use <b>openjdk version "17.0.8.1" or newer</b>. Follow https://www.java.com/en/download/manual.jsp for installation of Java.

Use <b>Apache Maven 3.6.3 or newer</b>. Follow https://www.baeldung.com/install-maven-on-windows-linux-mac for installation of Maven.

If you are running behind a proxy, follow https://www.baeldung.com/maven-behind-proxy for setting up proxy for Maven.

## Usage

Create a new SGX adapter, then use the adapter to collect quote from SGX enabled platform.
SGX enclave needs to expose a method for creating enclave report and must use SHA256 hash value as reportdata.

```java
// Create the SgxAdapter object
SgxAdapter sgx_adapter = new SgxAdapter(enclaveId[0], nonce, EnclaveLibrary.EnclaveFunction);

// Fetch the Sgx Quote
Evidence sgx_evidence = sgx_adapter.collectEvidence(nonce);
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
