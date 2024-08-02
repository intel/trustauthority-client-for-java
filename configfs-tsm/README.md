# Configfs-tsm

### Introduction
This Package wraps the configfs/tsm subsystem for generating attestation reports safely.<br/>

`Java version:` <b>v1.17</b> <br/>
`Kernel version:` <b>6.7+</b> <br/>

### `report` package

The TSM `report` subsystem provides a vendor-agnostic interface for collecting a
signed document for the Trusted Execution Environment's (TEE) state for remote
verification. For simplicity, we call this document an "attestation report",
though other sources may sometimes refer to it as a "quote".

Signing keys are expected to be rooted back to the manufacturer. Certificates
may be present in the `auxblob` attribute or as part of the report in `outblob`.

The core functionality of attestation report interaction is nonce in, report
out. For testability, we abstract the file operations that are needed for
creating configfs report entries, reading and writing attributes, and final
reclaiming of resources.

### `com.intel.trustauthority.configfsi` package
Most users will only want to use the client from `com.intel.trustauthority.linuxtsm.MakeClient()`.<br/> 
This package provides interface of [Client](src/main/java/com/intel/trustauthority/configfsi/Client.java)

### `com.intel.trustauthority.linuxtsm` package

<b> The linuxtsm package defines an implementation of  </b> 

```java
public static IClient com.intel.trustauthority.linuxtsm.TsmClient.makeClient() throws PathException
```


For further convenience, `linuxtsm` provides an alias for `makeClient` combined with `com.intel.trustauthority.report.Report.get()`<br/>


```java
public static Response com.intel.trustauthority.linuxtsm.TsmClient.getReport(Request request) throws IOException, ConfigfsExeception
```

Where

```java
public class Request {
	byte[] inBlob;
	Privilege privilege;
	boolean getAuxBlob;
}

public class Response {
	String provider;
	byte[] outBlob;
	byte[] auxBlob;
}

public class Privilege {
	int level;  
}
```
<b>Note: </b> The provider may not implement an AuxBlob delivery mechanism, so if GetAuxBlob is true, then AuxBlob still must be checked for length 0.


### Exceptions
[ConfigfsException](src/main/java/com/intel/trustauthority/exception/ConfigfsException.java) <br/>
[GenerationMismatchedException](src/main/java/com/intel/trustauthority/exception/GenerationMismatchedException.java) <br/>
[PathException](src/main/java/com/intel/trustauthority/exception/PathException.java) <br/>
[PrivLevelFormatException](src/main/java/com/intel/trustauthority/exception/PrivLevelFormatException.java) <br/>
[FakeTsmException](src/main/java/com/intel/trustauthority/exception/FakeTsmException.java) <br/>

### References
 [Kernel Documentation](https://www.kernel.org/doc/Documentation/ABI/testing/configfs-tsm)<br/>
 [go-configfs-tsm Implementation](https://github.com/google/go-configfs-tsm)<br/>
 