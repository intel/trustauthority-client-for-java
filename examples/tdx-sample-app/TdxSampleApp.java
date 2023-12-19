// Java Collections Imports
import java.util.Arrays;
import java.util.List;
import java.util.Map;

// Nimbus JOSE + JWT Library Import
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jose.util.Base64;

// Third-party Library Imports
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

// trust_authority_client imports
import trust_authority_client.TrustAuthorityConnector;
import trust_authority_client.TdxAdapter;
import trust_authority_client.Evidence;
import trust_authority_client.Config;
import trust_authority_client.AttestArgs;
import trust_authority_client.AttestResponse;

/**
 * TdxSampleApp class, a sample application demonstrating TDX Quote collection/verification
 * from TDX enabled platform
 */
public class TdxSampleApp {

    // Logger object
    private static final Logger logger = LogManager.getLogger(TdxSampleApp.class);

    public static void main(String[] args) {
        try {
            // For testing
            byte[] bytes = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};

            // Create the TdxAdapter object
            TdxAdapter tdx_adapter = new TdxAdapter(bytes, null);

            // Fetch the Tdx Quote
            Evidence tdx_evidence = tdx_adapter.collectEvidence(bytes);

            // Convert fetched TDX quote from bytes to Base64
            String base64Quote = Base64.encode(tdx_evidence.getEvidence()).toString();

            // Print the TDX fetched quote in Base64 format
            logger.debug("TDX fetched quote Base64 Encoded: " + base64Quote);

            // Convert fetched TDX UserData from bytes to Base64
            String base64UserData = Base64.encode(tdx_evidence.getUserData()).toString();

            // Print the TDX fetched UserData in Base64 format
            logger.debug("TDX fetched user data Base64 Encoded: " + base64UserData);

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
            AttestArgs attestArgs = new AttestArgs(tdx_adapter, null, trustauthority_request_id);
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