package amber_client;

import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public interface TrustConnector {
    byte[] getTokenSigningCertificates() throws Exception;

    GetNonceResponse getNonce(GetNonceArgs args) throws Exception;

    GetTokenResponse getToken(GetTokenArgs args) throws Exception;

    AttestResponse attest(AttestArgs args) throws Exception;

    Jws<Claims> verifyToken(String token) throws Exception;
}

interface EvidenceAdapter {
    Evidence collectEvidence(byte[] nonce) throws Exception;
}

class GetNonceArgs {
    String requestId;
}

class GetNonceResponse {
    VerifierNonce nonce;
    String[] headers;
}

class GetTokenArgs {
    VerifierNonce nonce;
    Evidence evidence;
    UUID[] policyIds;
    String requestId;
}

class GetTokenResponse {
    String token;
    String[] headers;
}

class AttestArgs {
    EvidenceAdapter adapter;
    UUID[] policyIds;
    String requestId;
}

class AttestResponse {
    String token;
    String[] headers;
}

class Evidence {
    int type;
    byte[] evidence;
    byte[] userData;
    byte[] eventLog;
}

class RetryConfig {
    Long retryWaitMin;  // Minimum time to wait between retries (in milliseconds)
    Long retryWaitMax;  // Maximum time to wait between retries (in milliseconds)
    Integer retryMax;   // Maximum number of retries

    // Implement your custom retry logic here
}

class Config {
    String baseUrl;
    SSLContext sslContext;
    String apiUrl;
    String apiKey;
    URL url;
    RetryConfig retryConfig;
}

class VerifierNonce {
    byte[] val;
    byte[] iat;
    byte[] signature;
}

class TrustConnectorImpl implements TrustConnector {
    private Config cfg;
    private CloseableHttpClient httpClient;
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

    TrustConnectorImpl(Config cfg) throws Exception {
        this.cfg = cfg;
        initializeHttpClient();
    }

    private void initializeHttpClient() throws Exception {
        if (cfg.sslContext == null) {
            cfg.sslContext = SSLContexts.custom()
                    .loadTrustMaterial(new TrustManager[] { new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }

                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        }

                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        }
                    }})
                    .build();
        }

        SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(cfg.sslContext,
                NoopHostnameVerifier.INSTANCE);
        
        RequestConfig requestConfig = RequestConfig.custom()
                .setSocketTimeout(5000)
                .setConnectTimeout(5000)
                .build();

        httpClient = HttpClients.custom()
                .setSSLSocketFactory(sslSocketFactory)
                .setDefaultRequestConfig(requestConfig)
                .build();
    }

    private byte[] concatenateByteArrays(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private byte[] readResponseBody(InputStream inputStream) throws Exception {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byteArrayOutputStream.write(buffer, 0, bytesRead);
        }
        byteArrayOutputStream.close();
        return byteArrayOutputStream.toByteArray();
    }

    public byte[] getTokenSigningCertificates() throws Exception {
        String url = String.format("%s/certs", cfg.baseUrl);

        HttpGet httpGet = new HttpGet(url);
        httpGet.setHeader(HttpHeaders.ACCEPT, mimeApplicationJson);

        HttpResponse response = httpClient.execute(httpGet);
        if (response.getStatusLine().getStatusCode() == 200) {
            return readResponseBody(response.getEntity().getContent());
        } else {
            // Handle error case
            return null;
        }
    }

    public GetNonceResponse getNonce(GetNonceArgs args) throws Exception {
        String url = String.format("%s/appraisal/v1/nonce", cfg.apiUrl);

        HttpGet httpGet = new HttpGet(url);
        httpGet.setHeader("HEADER_X_API_KEY", cfg.apiKey);
        httpGet.setHeader(HttpHeaders.ACCEPT, "MIME_APPLICATION_JSON");
        httpGet.setHeader("HEADER_REQUEST_ID", args.requestId);

        HttpResponse response = httpClient.execute(httpGet);
        if (response.getStatusLine().getStatusCode() == 200) {
            return processResponse(response);
        } else {
            // Handle error case
            return new GetNonceResponse();
        }
    }

    private GetNonceResponse processResponse(HttpResponse response) throws IOException {
        GetNonceResponse getNonceResponse = new GetNonceResponse();
        getNonceResponse.headers = response.getAllHeaders();

        byte[] responseBody = readResponseBody(response.getEntity().getContent());

        ObjectMapper objectMapper = new ObjectMapper();
        VerifierNonce verifierNonce = objectMapper.readValue(responseBody, VerifierNonce.class);

        getNonceResponse.nonce = verifierNonce;
        return getNonceResponse;
    }

    public AttestResponse attest(AttestArgs args) throws Exception {
        AttestResponse response = new AttestResponse();

        GetNonceResponse nonceResponse = getNonce(new GetNonceArgs(args.requestId));
        response.headers = nonceResponse.headers;

        if (nonceResponse.error != null) {
            return response;
        }

        byte[] combinedNonce = concatenateByteArrays(nonceResponse.nonce.val, nonceResponse.nonce.iat);
        Evidence evidence = args.adapter.collectEvidence(combinedNonce);
        if (evidence.error != null) {
            return response;
        }

        GetTokenResponse tokenResponse = getToken(
            new GetTokenArgs(nonceResponse.nonce, evidence, args.policyIds, args.requestId)
        );
        response.token = tokenResponse.token;
        response.headers = tokenResponse.headers;

        if (tokenResponse.error != null) {
            return response;
        }

        return response;
    }

    public GetTokenResponse getToken(GetTokenArgs args) throws Exception {
        String url = String.format("%s/appraisal/v1/attest", cfg.apiUrl);

        HttpPost httpPost = new HttpPost(url);
        httpPost.setHeader("x-api-key", cfg.apiKey);
        httpPost.setHeader(HttpHeaders.ACCEPT, "application/json");
        httpPost.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
        httpPost.setHeader("request-id", args.requestId);

        TokenRequest tokenRequest = new TokenRequest(args.evidence.evidence, args.nonce, args.evidence.userData, args.policyIds, args.evidence.eventLog);
        ObjectMapper objectMapper = new ObjectMapper();
        byte[] requestBody = objectMapper.writeValueAsBytes(tokenRequest);

        httpPost.setEntity(new ByteArrayEntity(requestBody));

        HttpResponse response = httpClient.execute(httpPost);
        if (response.getStatusLine().getStatusCode() == 200) {
            return processTokenResponse(response);
        } else {
            // Handle error case
            return new GetTokenResponse();
        }
    }

    private GetTokenResponse processTokenResponse(HttpResponse response) throws IOException {
        GetTokenResponse getTokenResponse = new GetTokenResponse();
        getTokenResponse.headers = response.getAllHeaders();

        byte[] responseBody = readResponseBody(response.getEntity().getContent());

        ObjectMapper objectMapper = new ObjectMapper();
        AttestationTokenResponse tokenResponse = objectMapper.readValue(responseBody, AttestationTokenResponse.class);

        getTokenResponse.token = tokenResponse.token;
        return getTokenResponse;
    }
}
