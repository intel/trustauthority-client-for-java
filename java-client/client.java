import java.io.*;
import java.net.*;

// AmberClient is an interface which exposes methods for calling Amber REST APIs
public interface AmberClient {

    // GetAmberCertificates() ([]byte, error)
    String GetAmberCertificates();

	// GetNonce(GetNonceArgs) (GetNonceResponse, error)
    GetNonceResponse GetNonce(GetNonceArgs);

	// GetToken(GetTokenArgs) (GetTokenResponse, error)
    GetTokenResponse GetToken(GetTokenArgs);

	// CollectToken(CollectTokenArgs) (CollectTokenResponse, error)
    CollectTokenResponse CollectToken(CollectTokenArgs);

	// VerifyToken(string) (*jwt.Token, error)
    Token VerifyToken(string);

};

// EvidenceAdapter is an interface which exposes methods for collecting Quote from Platform
public record EvidenceAdapter (String nonce) {
    Evidence CollectEvidence(String nonce);
}

// GetNonceArgs holds the request parameters needed for getting nonce from Amber
public record GetNonceArgs (String RequestId) {

}

// GetNonceResponse holds the response parameters recieved from nonce endpoint
public record GetNonceResponse (Nonce nonce, Header header) {

}

// GetTokenArgs holds the request parameters needed for getting token from Amber
public record GetTokenArgs (Nonce nonce, String RequestId, List<String> PolicyIds, Nonce nonce, Evidence evidence) {

}

// GetTokenResponse holds the response parameters recieved from attest endpoint
public record GetTokenResponse (String token, Header header) {

}

// CollectTokenArgs holds the request parameters needed for attestation with Amber
public record CollectTokenArgs (String RequestId, List<String> PolicyIds, Adapter evidence_adapter) {

}

// CollectTokenResponse holds the response parameters recieved during attestation flow
public record CollectTokenResponse (String token, Header header) {

}

// Evidence is used to store Quote to be sent for Attestation
public record Evidence (Integer type, String evidence, String userdata, String eventlog) {

}

// RetryConfig a retryable client configuration for automatic retries to tolerate minor outages.
public record RetryConfig (Integer RetryWaitMin, Integer RetryWaitMax, Integer RetryMax) {

}

// Config holds the Amber configuration for Client
public record Config (String baseurl, String apiurl, String apikey, String url) {

}

// VerifierNonce holds the signed nonce issued from Amber
public record VerifierNonce (String val, String iat, String signature) {

}

// amberClient manages communication with Amber V1 API
public record amberClient (Config config) {

}
