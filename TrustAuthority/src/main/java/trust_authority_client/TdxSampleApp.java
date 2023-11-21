package trust_authority_client;

// Nimbus JOSE + JWT Library Import
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jose.util.Base64;

/**
 * TdxSampleApp class, a sample application demonstrating TDX Quote collection/verification
 * from TDX enabled platform
 */
public class TdxSampleApp {

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
            System.out.println("TDX fetched quote Base64 Encoded: " + base64Quote);

            // Convert fetched TDX UserData from bytes to Base64
            String base64UserData = Base64.encode(tdx_evidence.getUserData()).toString();

            // Print the TDX fetched UserData in Base64 format
            System.out.println("TDX fetched user data Base64 Encoded: " + base64UserData);

            // Setting default arguments in case BaseURL, apiURL and apiKey are not provided
            String BaseURL = "http://localhost:8080";
            String apiURL = "http://localhost:8080";
            String apiKey = "apiKey";

            if (args.length != 3) {
                System.out.println("Incorrect arguments provided, using default arguments...");
            } else {
                BaseURL = args[0];
                apiURL = args[1];
                apiKey = args[2];
            }

            System.out.println("BaseURL: " + BaseURL + ", apiURL: " + apiURL + ", apiKey: " + apiKey);

            // Initialize config required for connector using BaseURL, apiURL and apiKey
            Config cfg = new Config(BaseURL, apiURL, apiKey);
    
            // Initializing connector with the config
            TrustAuthorityConnector connector = new TrustAuthorityConnector(cfg);

            // Testing attest API - internally tests GetNonce(), collectEvidence() and GetToken() API
            AttestArgs attestArgs = new AttestArgs(tdx_adapter, null, "req1");
            AttestResponse response = connector.attest(attestArgs);

            // Print the Token fetched from Trust Authority
            System.out.println("Token fetched from Trust Authority: " + response.getToken());

            // verify the received token
            JWTClaimsSet claims = connector.verifyToken(response.getToken());

            // Print the claims for the verified JWT
            System.out.println("Issuer: " + claims.getIssuer());
            System.out.println("Subject: " + claims.getSubject());
            System.out.println("Expiration Time: " + claims.getExpirationTime());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}