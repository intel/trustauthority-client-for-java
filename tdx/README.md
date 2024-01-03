# Intel® Trust Authority Java Client TDX Adapter
Java library for collecting TDX Quote from TDX enabled platform.

This library leverages Intel SGX DCAP for Quote generation: [https://github.com/intel/SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives)

## System Requirement

Use <b>Ubuntu 20.04</b>. 

Use <b>openjdk version "17.0.8.1" or newer</b>. Follow https://www.java.com/en/download/manual.jsp for installation of Java.

Use <b>Apache Maven 3.6.3 or newer</b>. Follow https://www.baeldung.com/install-maven-on-windows-linux-mac for installation of Maven.

If you are running behind a proxy, follow https://www.baeldung.com/maven-behind-proxy for setting up proxy for Maven.

## Usage

Create a new TDX adapter, then use the adapter to collect quote from TDX enabled platform.

```java
import com.intel.trustauthority.tdx.TdxAdapter;
import com.intel.trustauthority.connector.Evidence;

// Create the TdxAdapter object
TdxAdapter tdxAdapter = new TdxAdapter(nonce);

// Fetch the Tdx Quote
Evidence evidence = tdxAdapter.collectEvidence(nonce);
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
