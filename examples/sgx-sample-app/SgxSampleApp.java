// Java Collections Imports
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.security.SecureRandom;

// JNA (Java Native Access) Library Imports
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.Memory;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.TypeMapper;
import com.sun.jna.Structure.FieldOrder;
import com.sun.jna.Function;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.ByteByReference;

// Nimbus JOSE + JWT Library Import
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.JWTClaimsSet;

// Third-party Library Imports
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

// trust_authority_client imports
import trust_authority_client.TrustAuthorityConnector;
import trust_authority_client.SgxAdapter;
import trust_authority_client.Evidence;
import trust_authority_client.Config;
import trust_authority_client.AttestArgs;
import trust_authority_client.AttestResponse;

/**
 * EnclaveLibrary interface for creating enclave report
 * This interface extends the base Library class.
 */
interface EnclaveLibrary extends Library {

    // private variable to hold an instance of the native library interface
    EnclaveLibrary INSTANCE = (EnclaveLibrary) Native.loadLibrary("./sgx-example-enclave/enclave/enclave_library.so", EnclaveLibrary.class);

    // get_public_key() function to fetch the public key to be passed to SGXAdapter
    int get_public_key(long eid, PointerByReference pp_key, IntByReference p_key_size);

    // free_public_key() function to free the public key C variable
    void free_public_key(Pointer key);

    // Initialize the function pointer for enclave_create_report() function from enclave .so file
    Function myFunctionPointer = Function.getFunction("./sgx-example-enclave/enclave/enclave_library.so", "enclave_create_report");
}

/**
 * SgxSdkLibrary interface for creating the sgx enclave
 * This interface extends the base Library class.
 */
interface SgxSdkLibrary extends Library {

    // private variable to hold an instance of the native library sgx_urts interface
    SgxSdkLibrary INSTANCE = (SgxSdkLibrary) Native.loadLibrary("sgx_urts", SgxSdkLibrary.class);

    // Initialize the C native function sgx_create_enclave()
    int sgx_create_enclave(String enclaveFilePath, int debug, byte[] launchToken, IntByReference updated, long[] id, int[] misc_attr);

    // Initialize the C native function sgx_destroy_enclave()
    int sgx_destroy_enclave(long eid);
}

/**
 * SgxSampleApp class, a sample application demonstrating SGX Quote collection/verification
 * from SGX enabled platform
 */
public class SgxSampleApp {

    // Logger object
    private static final Logger logger = LogManager.getLogger(SgxSampleApp.class);

    public static void main(String[] args) {
        try {
            // Path of enclave .so file
            String enclavePath = "./sgx-example-enclave/enclave/enclave.signed.so";

            // Initialize SGX enclave related variables
            long[] enclaveId = new long[1];
            IntByReference updated = new IntByReference(0);
            byte[] launchToken = new byte[1024];
            int[] miscAttr = new int[1];

            // Create SGX enclave
            int result = SgxSdkLibrary.INSTANCE.sgx_create_enclave(enclavePath, 0, launchToken, updated, enclaveId, miscAttr);
            if (result != 0) {
                logger.error("Failed to create enclave: " + Integer.toHexString(result));
            } else {
                logger.info("Enclave created successfully. Enclave ID: " + enclaveId[0]);
            }

            // Initialize get_public_key() API variables
            PointerByReference pp_key = new PointerByReference();
            IntByReference p_key_size = new IntByReference();

            // Call get_public_key() and fetch the public key to be passed to SgxAdapter
            int ret = EnclaveLibrary.INSTANCE.get_public_key(enclaveId[0], pp_key, p_key_size);
            if (ret != 0) {
                System.err.println("Error: Failed to retrieve key from sgx enclave");
                return;
            }

            // Fetch the output values of get_public_key() call to convert it to Java variables
            Pointer keyPointer = pp_key.getValue();
            int keySize = p_key_size.getValue();

            // Convert the C bytes to Java bytes
            byte[] keyBytes = keyPointer.getByteArray(0, keySize);
            // Free the C bytes
            EnclaveLibrary.INSTANCE.free_public_key(keyPointer);

            // Create the SgxAdapter object
            SgxAdapter sgx_adapter = new SgxAdapter(enclaveId[0], keyBytes, EnclaveLibrary.myFunctionPointer);

            // Fetch the Sgx Quote
            Evidence sgx_evidence = sgx_adapter.collectEvidence(keyBytes);

            // Convert fetched SGX quote from bytes to Base64
            String base64Quote = Base64.encode(sgx_evidence.getEvidence()).toString();

            // Print the SGX fetched quote in Base64 format
            logger.debug("SGX fetched quote Base64 Encoded: " + base64Quote);

            // Convert fetched SGX UserData from bytes to Base64
            String base64UserData = Base64.encode(sgx_evidence.getUserData()).toString();

            // Print the SGX fetched UserData in Base64 format
            logger.debug("SGX fetched user data Base64 Encoded: " + base64UserData);

            // Fetch proxy settings from environment
            String httpsHost = System.getenv("HTTPS_PROXY_HOST");
            if (httpsHost == null) {
                logger.warn("HTTPS_PROXY_HOST is not set.");
            }
            String httpsPort = System.getenv("HTTPS_PROXY_PORT");
            if (httpsPort == null) {
                logger.warn("HTTPS_PROXY_PORT is not set.");
            }
            logger.debug("HTTPS_PROXY_HOST: " + httpsHost + ", HTTPS_PROXY_PORT: " + httpsPort);

            // Setting proxy settings
            System.setProperty("https.proxyHost", httpsHost);
            System.setProperty("https.proxyPort", httpsPort);

            // Fetch TRUSTAUTHORITY_BASE_URL, TRUSTAUTHORITY_API_URL and TRUSTAUTHORITY_API_KEY from environment
            String trustauthority_base_url = System.getenv("TRUSTAUTHORITY_BASE_URL");
            if (trustauthority_base_url == null) {
                logger.error("TRUSTAUTHORITY_BASE_URL is not set.");
            }
            String trustauthority_api_url = System.getenv("TRUSTAUTHORITY_API_URL");
            if (trustauthority_api_url == null) {
                logger.error("TRUSTAUTHORITY_API_URL is not set.");
            }
            String trustauthority_api_key = System.getenv("TRUSTAUTHORITY_API_KEY");
            if (trustauthority_api_key == null) {
                logger.error("TRUSTAUTHORITY_API_KEY is not set.");
            }
            String trustauthority_request_id = System.getenv("TRUSTAUTHORITY_REQUEST_ID");
            if (trustauthority_request_id == null) {
                logger.error("TRUSTAUTHORITY_REQUEST_ID is not set.");
            }
            logger.debug("TRUSTAUTHORITY_BASE_URL: " + trustauthority_base_url + ", TRUSTAUTHORITY_API_URL: " + trustauthority_api_url + ", TRUSTAUTHORITY_API_KEY: " + trustauthority_api_key);

            // Initialize config required for connector using TRUSTAUTHORITY_BASE_URL, TRUSTAUTHORITY_API_URL and TRUSTAUTHORITY_API_KEY
            Config cfg = new Config(trustauthority_base_url, trustauthority_api_url, trustauthority_api_key);

            // Initializing connector with the config
            TrustAuthorityConnector connector = new TrustAuthorityConnector(cfg);

            // Testing attest API - internally tests GetNonce(), collectEvidence() and GetToken() API
            AttestArgs attestArgs = new AttestArgs(sgx_adapter, null, trustauthority_request_id);
            AttestResponse response = connector.attest(attestArgs);

            // Print the Token fetched from Trust Authority
            logger.info("Token fetched from Trust Authority: " + response.getToken());

            // Print the Request ID of token fetched from Trust Authority
            if (response.getHeaders().containsKey("request-id")) {
                // Print Request ID of fetched token
                logger.info("Request ID of fetched token: " + response.getHeaders().get("request-id"));
            } else {
                logger.warn("request-id not found in response token.");
            }
            // Print the Trace ID of token fetched from Trust Authority
            if (response.getHeaders().containsKey("trace-id")) {
                // Print Trace ID of fetched token
                logger.info("Trace ID of fetched token: " + response.getHeaders().get("trace-id"));
            } else {
                logger.warn("trace-id not found in response token.");
            }

            // verify the received token
            JWTClaimsSet claims = connector.verifyToken(response.getToken());

            // Print the claims for the verified JWT
            logger.info("Issuer: " + claims.getIssuer());
            logger.info("Subject: " + claims.getSubject());
            logger.info("Expiration Time: " + claims.getExpirationTime());
        } catch (Exception e) {
            logger.error("Exception: " + e);
        }
    }
}