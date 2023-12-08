#!/bin/bash -e

# Load environment variables from .env file
[ ! -f .env ] || export $(grep -v '^#' .env | xargs)

# Check if Trust Authority arguments are provided
if [ $# -ne 3 ]; then
    echo "Usage: $0 <TRUSTAUTHORITY_BASE_URL> <TRUSTAUTHORITY_API_URL> <TRUSTAUTHORITY_API_KEY>"
    exit 1
fi

# Start the TdxSampleApp
java -Dhttps.proxyHost="proxy-fm.intel.com" -Dhttps.proxyPort="911" -cp /root/.m2/repository/org/bouncycastle/bcprov-jdk15on/1.68/bcprov-jdk15on-1.68.jar:/root/.m2/repository/com/fasterxml/jackson/core/jackson-annotations/2.13.0/jackson-annotations-2.13.0.jar:/root/.m2/repository/com/fasterxml/jackson/core/jackson-databind/2.13.0/jackson-databind-2.13.0.jar:/root/.m2/repository/com/fasterxml/jackson/core/jackson-core/2.13.0/jackson-core-2.13.0.jar:/root/.m2/repository/net/java/dev/jna/jna/5.9.0/jna-5.9.0.jar:/root/.m2/repository/com/google/code/gson/gson/2.9.0/gson-2.9.0.jar:/root/.m2/repository/io/jsonwebtoken/jjwt/0.12.3/jjwt-0.12.3.jar:target/trust-authority-client-java-1.0.0.jar:/root/.m2/repository/io/jsonwebtoken/jjwt-impl/0.11.2/jjwt-impl-0.11.2.jar:/root/.m2/repository/io/jsonwebtoken/jjwt-api/0.11.2/jjwt-api-0.11.2.jar:/root/.m2/repository/io/jsonwebtoken/jjwt-jackson/0.11.2/jjwt-jackson-0.11.2.jar:/root/.m2/repository/com/nimbusds/nimbus-jose-jwt/9.10/nimbus-jose-jwt-9.10.jar:/root/.m2/repository/com/fasterxml/jackson/core/jackson-core/2.13.0/jackson-core-2.13.0.jar trust_authority_client.TdxSampleApp $1 $2 $3