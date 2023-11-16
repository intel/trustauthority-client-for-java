# Intel® Trust Authority Java Client
Intel Trust Authority Java Client provides a set of Java modules and command line interfaces for attesting different TEEs with Intel Trust Authority.
It is flexible enough that either the users can import the Java modules within their application or they can directly invoke the CLIs from their application.

## Modes of Integration

The Client provides following modules which can be imported by an application to attest the SGX and TDX TEEs with Intel Trust Authority:
1. [connector](./TrustAuthority/src/main/java/trust_authority_client/TrustAuthorityConnector.java): Provides an HTTPClient interface to communicate with Intel Trust Authority via REST APIs.
2. [sgx](./TrustAuthority/src/main/java/trust_authority_client/SgxAdapter.java): Implements an EvidenceAdapter interface to collect the SGX quote.
<!-- 3. [java-tdx](./java-tdx): Implements an EvidenceAdapter interface to collect the TDX quote. -->

<!-- The Client additionally provides following command line interfaces which can be directly invoked by an application to attest the TDX TEE with Intel Trust Authority:
1. [tdx-cli](./tdx-cli): Provides a command line interface to attest the TDX TEE(TD) with Intel Trust Authority. -->

## Java Requirement

Use <b>openjdk version "17.0.8.1" or newer</b>. Follow https://www.java.com/en/download/manual.jsp for installation of Java.

## Maven Requirement

Use <b>Apache Maven 3.6.3 or newer</b>. Follow https://www.baeldung.com/install-maven-on-windows-linux-mac for installation of Maven.

If you are running behind a proxy, follow https://www.baeldung.com/maven-behind-proxy for setting up proxy for Maven.

## License

This library is distributed under the BSD-style license found in the [LICENSE](./LICENSE)
file.
