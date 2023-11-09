package trust_authority_client;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.UUID;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.PKIXParameters;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CRL;
import java.security.cert.CRLSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509CertSelector;
import java.security.Security;
import java.security.Provider;
import java.security.SecurityPermission;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Arrays;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;

import java.net.HttpURLConnection;
import java.io.IOException;
import java.net.URL;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.HashSet;
import java.util.Collections;
import java.util.stream.Collectors;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Extension;
import java.security.cert.CertificateException;
import java.security.Key;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;

import com.google.common.io.ByteStreams;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonElement;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.WeakKeyException;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.List;
import java.util.UUID;
import java.nio.charset.StandardCharsets;
import org.apache.commons.io.IOUtils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.security.cert.CertificateException;

class Constants {
    public static final String HEADER_X_API_KEY = "x-api-key";
    public static final String HEADER_ACCEPT = "Accept";
    public static final String HEADER_CONTENT_TYPE = "Content-Type";
    public static final String HEADER_REQUEST_ID = "request-id";
    public static final String HEADER_TRACE_ID = "trace-id";

    public static final String MIME_APPLICATION_JSON = "application/json";
    public static final int ATS_CERT_CHAIN_MAX_LEN = 10;
    public static final int MAX_RETRIES = 2;
    public static final int DEFAULT_RETRY_WAIT_MIN_SECONDS = 2;
    public static final int DEFAULT_RETRY_WAIT_MAX_SECONDS = 10;
    public static final String SERVICE_UNAVAILABLE_ERROR = "service unavailable";

    public static final String headerXApiKey = "X-Api-Key";
    public static final String headerAccept = "Accept";
    public static final String headerContentType = "Content-Type";
    public static final String HeaderRequestId = "RequestId";
    public static final String mimeApplicationJson = "application/json";

    public static final int AtsCertChainMaxLen = 5; // Set the maximum length of the certificate chain
}

class GetNonceResponse {
    private VerifierNonce nonce;
    private Map<String, List<String>> headers;
    private String error;

    public GetNonceResponse() {
        headers = new HashMap<>();
    }

    public VerifierNonce getNonce() {
        return nonce;
    }

    public void setNonce(VerifierNonce nonce) {
        this.nonce = nonce;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    public void setHeaders(Map<String, List<String>> headers) {
        this.headers = headers;
    }

    public String getError() {
        return this.error;
    }

    public void setError(String error) {
        this.error = error;
    }
}

class GetTokenResponse {
    private String token;
    private Map<String, List<String>> headers;
    private String error;

    public GetTokenResponse(String token, Map<String, List<String>> headers) {
        this.token = token;
        this.headers = headers;
    }

    public String getToken() {
        return token;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    public void getToken(String token) {
        this.token = token;
    }

    public void setHeaders(Map<String, List<String>> headers) {
        this.headers = headers;
    }

    public String getError() {
        return this.error;
    }
}

class AttestResponse {
    private String token;
    private Map<String, List<String>> headers;

    public AttestResponse() {
    }

    public AttestResponse(String token, Map<String, List<String>> headers) {
        this.token = token;
        this.headers = headers;
    }

    public String getToken() {
        return token;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    public void setHeaders(Map<String, List<String>> headers) {
        this.headers = headers;
    }

    public void setToken(String token) {
        this.token = token;
    }
}

class GetNonceArgs {
    private String requestId;

    public GetNonceArgs(String requestId) {
        this.requestId = requestId;
    }

    public String getRequestId() {
        return requestId;
    }
}

class GetTokenArgs {
    private VerifierNonce nonce;
    private Evidence evidence;
    private List<UUID> policyIds;
    private String requestId;

    public GetTokenArgs(VerifierNonce nonce, Evidence evidence, List<UUID> policyIds, String requestId) {
        this.nonce = nonce;
        this.evidence = evidence;
        this.policyIds = policyIds;
        this.requestId = requestId;
    }

    public VerifierNonce getNonce() {
        return nonce;
    }

    public Evidence getEvidence() {
        return evidence;
    }

    public List<UUID> getPolicyIds() {
        return policyIds;
    }

    public String getRequestId() {
        return requestId;
    }
}

interface EvidenceAdapter {
    Evidence collectEvidence(byte[] nonce) throws Exception;
}

class AttestArgs {
    private EvidenceAdapter adapter;
    private List<UUID> policyIds;
    private String requestId;

    public AttestArgs() {
    }

    public AttestArgs(EvidenceAdapter adapter, List<UUID> policyIds, String requestId) {
        this.adapter = adapter;
        this.policyIds = policyIds;
        this.requestId = requestId;
    }

    public EvidenceAdapter getAdapter() {
        return adapter;
    }

    public List<UUID> getPolicyIds() {
        return policyIds;
    }

    public String getRequestId() {
        return requestId;
    }

    public void setAdapter(EvidenceAdapter adapter) {
        this.adapter = adapter;
    }

    public void setPolicyIds(List<UUID> policyIds) {
        this.policyIds = policyIds;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }
}

class Evidence {
    private long type;
    private byte[] evidence;
    private byte[] userData;
    private byte[] eventLog;
    private String error;

    public Evidence(long type, byte[] evidence, byte[] userData, byte[] eventLog) {
        this.type = type;
        this.evidence = evidence;
        this.userData = userData;
        this.eventLog = eventLog;
    }

    public long getType() {
        return type;
    }

    public byte[] getEvidence() {
        return evidence;
    }

    public byte[] getUserData() {
        return userData;
    }

    public byte[] getEventLog() {
        return eventLog;
    }

    public String getError() {
        return this.error;
    }

    public void setError(String error) {
        this.error = error;
    }
}

class RetryConfig {
    private Long retryWaitMin;
    private Long retryWaitMax;
    private Integer retryMax;

    public RetryConfig() {
    }

    public Long getRetryWaitMin() {
        return retryWaitMin;
    }

    public Long getRetryWaitMax() {
        return retryWaitMax;
    }

    public Integer getRetryMax() {
        return retryMax;
    }
}

class Config {
    private String baseUrl;
    private String apiUrl;
    private String apiKey;
    private URL url;
    private RetryConfig retryConfig;

    public Config(String baseUrl, String apiUrl, String apiKey) throws Exception {
        this.baseUrl = baseUrl;
        this.apiUrl = apiUrl;
        this.apiKey = apiKey;
        this.url = new URL(baseUrl);
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public String getApiUrl() {
        return apiUrl;
    }

    public String getApiKey() {
        return apiKey;
    }

    public URL getUrl() {
        return url;
    }

    public RetryConfig getRetryConfig() {
        return retryConfig;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public void setApiUrl(String apiUrl) {
        this.apiUrl = apiUrl;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public void setUrl(URL url) {
        this.url = url;
    }
}

class RetryableStatusCode {
    private static Set<Integer> retryableStatusCodes;

    static {
        retryableStatusCodes = new HashSet<>();
        retryableStatusCodes.add(500);
        retryableStatusCodes.add(503);
        retryableStatusCodes.add(504);
    }

    public static boolean isRetryable(int statusCode) {
        return retryableStatusCodes.contains(statusCode);
    }
}

class DefaultRetryPolicy {
    public static boolean shouldRetry(HttpURLConnection connection, IOException err) {
        if (Thread.interrupted()) {
            return false;
        }

        if (err instanceof java.net.SocketTimeoutException) {
            // If connection was closed due to client timeout, retry again
            return true;
        }

        if (err instanceof java.net.UnknownHostException) {
            // If the request did not reach the API gateway and the error is Service Unavailable
            return true;
        }

        return false;
    }
}

class VerifierNonce {
    private byte[] val;
    private byte[] iat;
    private byte[] signature;

    public VerifierNonce() {
    }

    public VerifierNonce(byte[] val, byte[] iat, byte[] signature) {
        this.val = val;
        this.iat = iat;
        this.signature = signature;
    }

    public byte[] getVal() {
        return val;
    }

    public void setVal(byte[] val) {
        this.val = val;
    }

    public byte[] getIat() {
        return iat;
    }

    public void setIat(byte[] iat) {
        this.iat = iat;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }
}

class TokenRequest {
    private byte[] quote;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("verifier_nonce")
    private VerifierNonce verifierNonce;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("runtime_data")
    private byte[] runtimeData;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("policy_ids")
    private List<UUID> policyIds;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("event_log")
    private byte[] eventLog;

    public TokenRequest() {
    }

    public TokenRequest(byte[] quote, VerifierNonce verifierNonce, byte[] runtimeData, List<UUID> policyIds, byte[] eventLog) {
        this.quote = quote;
        this.verifierNonce = verifierNonce;
        this.runtimeData = runtimeData;
        this.policyIds = policyIds;
        this.eventLog = eventLog;
    }

    public byte[] getQuote() {
        return quote;
    }

    public void setQuote(byte[] quote) {
        this.quote = quote;
    }

    public VerifierNonce getVerifierNonce() {
        return verifierNonce;
    }

    public void setVerifierNonce(VerifierNonce verifierNonce) {
        this.verifierNonce = verifierNonce;
    }

    public byte[] getRuntimeData() {
        return runtimeData;
    }

    public void setRuntimeData(byte[] runtimeData) {
        this.runtimeData = runtimeData;
    }

    public List<UUID> getPolicyIds() {
        return policyIds;
    }

    public void setPolicyIds(List<UUID> policyIds) {
        this.policyIds = policyIds;
    }

    public byte[] getEventLog() {
        return eventLog;
    }

    public void setEventLog(byte[] eventLog) {
        this.eventLog = eventLog;
    }
}

interface ResponseProcessor {
    void process(HttpURLConnection connection) throws Exception;
}

class ConnectorException extends Exception {
    public ConnectorException(String message) {
        super(message);
    }
}

public class TrustAuthorityConnector {

    // private static final Logger logger = LogManager.getLogger(TrustAuthorityConnector.class);

    private Config cfg;
    private String tokenSigningCertificates; // Replace with your actual token signing certificates
    private String caCertificates; // Replace with your actual CA certificates
    private String atsCACertificates; // Replace with your actual ATS CA certificates

    public TrustAuthorityConnector() {
    }

    public TrustAuthorityConnector(Config cfg, String tokenSigningCertificates, String caCertificates, String atsCACertificates) {
        this.cfg = cfg;
        this.tokenSigningCertificates = tokenSigningCertificates;
        this.caCertificates = caCertificates;
        this.atsCACertificates = atsCACertificates;
    }

    public Config getConfig() {
        return cfg;
    }

    public void setEventLog(Config cfg) {
        this.cfg = cfg;
    }

    public String gettokenSigningCertificates() {
        return tokenSigningCertificates;
    }

    public void setTokenSigningCertificates(String tokenSigningCertificates) {
        this.tokenSigningCertificates = tokenSigningCertificates;
    }

    public String getCaCertificates() {
        return caCertificates;
    }

    public void setCaCertificates(String caCertificates) {
        this.caCertificates = caCertificates;
    }

    public String getAtsCACertificates() {
        return atsCACertificates;
    }

    public void setAtsCACertificates(String atsCACertificates) {
        this.atsCACertificates = atsCACertificates;
    }

    public GetNonceResponse GetNonce(GetNonceArgs args) throws Exception {
        String url = String.format("%s/appraisal/v1/nonce", cfg.getApiUrl());

        HttpURLConnection connection = createConnection(url, "GET");
        connection.setRequestProperty(Constants.HEADER_X_API_KEY, cfg.getApiKey());
        connection.setRequestProperty(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON);
        connection.setRequestProperty(Constants.HEADER_REQUEST_ID, args.getRequestId());

        GetNonceResponse response = new GetNonceResponse();
        processResponse(connection, response);

        return response;
    }

    public GetTokenResponse GetToken(GetTokenArgs args) throws IOException {
        String url = String.format("%s/appraisal/v1/attest", cfg.getApiUrl());

        TokenRequest tr = new TokenRequest(args.getEvidence().getEvidence(), args.getNonce(),
                                           args.getEvidence().getUserData(), args.getPolicyIds(),
                                           args.getEvidence().getEventLog());

        // TODO: Uncomment this line once sgx/tdx are in place
        // String body = new Gson().toJson(tr);
        // HttpURLConnection conn = createConnection(url, "POST", body, args.getRequestId());

        HttpURLConnection conn = createConnection(url, "POST", "{\"a\":\"b\"}", args.getRequestId());

        try {
            int responseCode = conn.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new IOException("HTTP error code: " + responseCode);
            } else {
                
            }
            String responseBody = readResponseBody(conn);

            Gson gson = new Gson();

            JsonObject jsonObject = gson.fromJson(responseBody, JsonObject.class);
            String token = jsonObject.get("token").getAsString();

            return new GetTokenResponse(token, conn.getHeaderFields());
        } finally {
            conn.disconnect();
        }
    }
    
    // Attest is used to initiate remote attestation with Trust Authority
    public AttestResponse attest(AttestArgs args) throws Exception {
        AttestResponse response = new AttestResponse();

        GetNonceResponse nonceResponse = GetNonce(new GetNonceArgs(args.getRequestId()));
        response.setHeaders(nonceResponse.getHeaders());
        
        if (nonceResponse.getError() != null) {
            throw new Exception("Failed to collect nonce from Trust Authority: " + nonceResponse.getError());
        }

        byte[] nonceValue = nonceResponse.getNonce().getVal();
        byte[] iat = nonceResponse.getNonce().getIat();
        byte[] combinedNonce = new byte[nonceValue.length + iat.length];
        System.arraycopy(nonceValue, 0, combinedNonce, 0, nonceValue.length);
        System.arraycopy(iat, 0, combinedNonce, nonceValue.length, iat.length);

        Evidence evidence = args.getAdapter().collectEvidence(combinedNonce);
        
        if (evidence.getError() != null) {
            throw new Exception("Failed to collect evidence from adapter: " + evidence.getError());
        }

        GetTokenResponse tokenResponse = GetToken(new GetTokenArgs(nonceResponse.getNonce(), evidence, args.getPolicyIds(), args.getRequestId()));
        response.setToken(tokenResponse.getToken());
        response.setHeaders(tokenResponse.getHeaders());
        
        if (tokenResponse.getError() != null) {
            throw new Exception("Failed to collect token from Trust Authority: " + tokenResponse.getError());
        }

        return response;
    }

    // GetTokenSigningCertificates is used to get Trust Authority attestation token signing certificates
    public byte[] getTokenSigningCertificates() throws Exception {
        String url = String.format("%s/certs", cfg.getBaseUrl());

        URL endpointUrl = new URL(url);
        HttpURLConnection connection = (HttpURLConnection) endpointUrl.openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Accept", "application/json");

        ByteArrayOutputStream responseStream = new ByteArrayOutputStream();
        
        try {
            if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = connection.getInputStream().read(buffer)) != -1) {
                    responseStream.write(buffer, 0, bytesRead);
                }
            } else {
                throw new Exception("Failed to read body from " + url);
            }
        } finally {
            connection.disconnect();
        }

        return responseStream.toByteArray();
    }

    private HttpURLConnection createConnection(String url, String method) throws IOException {
        URL requestUrl = new URL(url);
        HttpURLConnection connection = (HttpURLConnection) requestUrl.openConnection();
        connection.setRequestMethod(method);
        connection.setConnectTimeout(0);
        connection.setReadTimeout(0);

        return connection;
    }

    private void processResponse(HttpURLConnection connection, GetNonceResponse response) throws IOException {
        response.setHeaders(connection.getHeaderFields());

        int responseCode = connection.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_OK) {
            String responseBody = readResponseBody(connection);
            // ObjectMapper mapper = new ObjectMapper();
            // VerifierNonce nonce = mapper.readValue(responseBody, VerifierNonce.class);

            // TODO: Process this better and fill in val, iat and signature
            String charsetName = "UTF-8";
            VerifierNonce nonce = new VerifierNonce(responseBody.getBytes(charsetName), responseBody.getBytes(charsetName),
                                                    responseBody.getBytes(charsetName));
            response.setNonce(nonce);
        } else {
            // Handle error response
            // You can throw an exception or handle it as needed
        }
    }

    private String readResponseBody(HttpURLConnection connection) throws IOException {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
        }
        return content.toString();
    }

    private HttpURLConnection createConnection(String url, String method, String requestBody, String requestId) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod(method);
        conn.setDoOutput(true);
        conn.setRequestProperty(Constants.headerXApiKey, cfg.getApiKey());
        conn.setRequestProperty(Constants.headerAccept, Constants.mimeApplicationJson);
        conn.setRequestProperty(Constants.headerContentType, Constants.mimeApplicationJson);
        conn.setRequestProperty(Constants.HeaderRequestId, requestId);

        if (requestBody != null) {
            conn.getOutputStream().write(requestBody.getBytes("UTF-8"));
        }

        return conn;
    }

    public X509CRL getCRL(List<String> crlArr) throws IOException {
        if (crlArr.isEmpty()) {
            throw new IOException("Invalid CDP count present in the certificate");
        }

        String crlUrl = crlArr.get(0);
        try {
            new URL(crlUrl).toURI();
        } catch (Exception e) {
            throw new IOException("Invalid CRL distribution point");
        }

        HttpURLConnection conn = createConnection(crlUrl, "GET", null, null);

        try {
            int responseCode = conn.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new IOException("HTTP error code: " + responseCode);
            }

            String responseBody = readResponseBody(conn);
            String charsetName = "UTF-8";

            // Create an InputStream from the byte array
            InputStream inputStream = new ByteArrayInputStream(responseBody.getBytes(charsetName));

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(inputStream);

            return crl;
        } catch (Exception e) {
            throw new IOException(e);
        } finally {
            conn.disconnect();
        }
    }

    public boolean isSignatureValid(X509CRL crl, X509Certificate caCert) {
        try {
            // Verify the CRL's signature against the CA's public key
            crl.verify(caCert.getPublicKey());
            System.out.println("CRL signature is valid.");
            return true;
        } catch (Exception e) {
            System.err.println("CRL signature is not valid: " + e.getMessage());
            return false;
        }
    }

    public boolean verifyCRL(X509CRL crl, X509Certificate leafCert, X509Certificate caCert) throws Exception {
        if (leafCert == null || caCert == null || crl == null) {
            throw new Exception("Leaf Cert or CA Cert or CRL is null");
        }

        if (!isSignatureValid(crl, caCert)) {
            throw new Exception("CRL signature verification failed");
        }

        Date now = new Date();
        if (crl.getNextUpdate().before(now)) {
            throw new Exception("Outdated CRL");
        }

        for (X509CRLEntry entry : crl.getRevokedCertificates()) {
            if (entry.getSerialNumber().equals(leafCert.getSerialNumber())) {
                throw new Exception("Certificate was Revoked");
            }
        }
        return true;
    }

    public List<X509Certificate> getX509CertChainFromJWK(JWK jwk) throws CertificateException {
        if (jwk instanceof RSAKey) {
            RSAKey rsaKey = (RSAKey) jwk;
            List<Base64> base64CertList = rsaKey.getX509CertChain();
            List<X509Certificate> x509CertChain = new ArrayList<>();

            if (base64CertList != null && !base64CertList.isEmpty()) {
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                for (Base64 base64Cert : base64CertList) {
                    byte[] certBytes = base64Cert.decode();
                    X509Certificate x509Cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));
                    x509CertChain.add(x509Cert);
                }
                return x509CertChain;
            } else {
                throw new CertificateException("No X.509 certificate chain found in the RSA JWK.");
            }
        } else {
            throw new CertificateException("Unsupported JWK type. Expecting an RSA JWK.");
        }
    }

    public List<String> getCRLDistributionPoints(X509Certificate cert) {
        try {
            byte[] crlDistributionPointsExtensionValue = cert.getExtensionValue("2.5.29.31");
            if (crlDistributionPointsExtensionValue != null) {
                // Extract the extension value and decode it
                byte[] crlDistributionPointsExtensionData = Arrays.copyOfRange(crlDistributionPointsExtensionValue, 2, crlDistributionPointsExtensionValue.length);
                InputStream is = new ByteArrayInputStream(crlDistributionPointsExtensionData);
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                Collection<X509CRL> crls = (Collection<X509CRL>) certificateFactory.generateCRLs(is);
                
                List<String> crlDistributionPoints = new ArrayList<>();
                
                for (X509CRL crl : crls) {
                    // Access the CRL distribution points from the CRL extension
                    String crlDistributionPoint = crl.getIssuerX500Principal().getName();
                    crlDistributionPoints.add(crlDistributionPoint);
                }
                return crlDistributionPoints;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public JWSObject verifyToken(String token) throws Exception {

        try {
            JWSObject jwsObject = JWSObject.parse(token);
            Payload payload = jwsObject.getPayload();

            // Fetch kid from parsed token
            String kid = jwsObject.getHeader().getKeyID();
            if (kid == null) {
                throw new IllegalArgumentException("kid field missing in token header");
            }

            // Fetch certs from getTokenSigningCertificates() API
            String jwks = getTokenSigningCertificates().toString();

            // Parse the JWKSet string
            JWKSet jwkSet = JWKSet.parse(jwks);

            JWK jwkKey = jwkSet.getKeyByKeyId(kid);
            if (jwkKey == null) {
                throw new IllegalArgumentException("Could not find Key matching the key id");
            }

            int AtsCertChainMaxLen = 10;
            List<X509Certificate> atsCerts = getX509CertChainFromJWK(jwkKey);
            if (atsCerts.size() > AtsCertChainMaxLen) {
                throw new IllegalArgumentException("Token Signing Cert chain has more than " + AtsCertChainMaxLen + " certificates");
            }

            List<X509Certificate> rootCerts = new LinkedList<>();
            List<X509Certificate> intermediateCerts = new LinkedList<>();
            X509Certificate leafCert = null;

            for (X509Certificate atsCert : atsCerts) {
                if (atsCert.getBasicConstraints() > -1 && atsCert.getSubjectDN().getName().contains("Root CA")) {
                    rootCerts.add(atsCert);
                } else if (atsCert.getSubjectDN().getName().contains("Signing CA")) {
                    intermediateCerts.add(atsCert);
                } else {
                    leafCert = atsCert;
                }
            }
            
            X509CRL rootCrl = getCRL(getCRLDistributionPoints(intermediateCerts.get(0)));
            if (!verifyCRL(rootCrl, intermediateCerts.get(0), rootCerts.get(0))) {
                throw new IllegalArgumentException("Failed to check ATS CA Certificate against Root CA CRL");
            }
            
            X509CRL atsCrl = getCRL(getCRLDistributionPoints(leafCert));
            if (!verifyCRL(atsCrl, leafCert, intermediateCerts.get(0))) {
                throw new IllegalArgumentException("Failed to check ATS Leaf certificate against ATS CRL");
            }

            return jwsObject;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private X509Certificate parseX509Certificate(String pemCertificate) {
        // Parse the PEM-encoded X.509 certificate
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            byte[] bytes = pemCertificate.getBytes("UTF-8");
            ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
            return (X509Certificate) cf.generateCertificate(inputStream);
        } catch (Exception e) {
            System.out.println("Failed to parse X.509 certificate");
            return null;
        }
    }
}
