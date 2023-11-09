// package trust_authority_client;

// import com.nimbusds.jose.JWSObject;
// import com.nimbusds.jose.Payload;
// import com.nimbusds.jose.jwk.JWKSet;
// import com.nimbusds.jose.jwk.RSAKey;
// import com.nimbusds.jose.jwk.JWK;
// import com.nimbusds.jwt.JWTClaimsSet;
// import java.security.cert.X509Certificate;
// import java.util.List;
// import java.util.LinkedList;

// import com.nimbusds.jose.jwk.JWK;
// import com.nimbusds.jose.jwk.JWKSet;
// import com.nimbusds.jose.jwk.RSAKey;

// import java.io.IOException;
// import java.net.URL;
// import java.security.cert.X509Certificate;
// import java.security.cert.CertificateFactory;

// import java.io.IOException;
// import java.io.ByteArrayInputStream;

// import com.nimbusds.jose.jwk.JWK;
// import com.nimbusds.jose.jwk.RSAKey;
// import java.security.cert.X509Certificate;
// import java.security.cert.CertificateFactory;
// import java.security.cert.CertificateEncodingException;
// import java.security.cert.CertificateException;
// import java.util.ArrayList;
// import java.util.List;

// import com.nimbusds.jose.jwk.JWK;
// import com.nimbusds.jose.jwk.RSAKey;
// import com.nimbusds.jose.util.Base64;
// import java.io.ByteArrayInputStream;
// import java.security.cert.X509Certificate;
// import java.security.cert.CertificateFactory;
// import java.security.cert.CertificateException;
// import java.util.ArrayList;
// import java.util.List;

// import java.security.cert.X509CRL;
// import java.security.cert.X509CRLEntry;

// import java.security.cert.CertificateParsingException;
// import java.security.cert.X509CRL;
// import java.security.cert.X509Certificate;
// import java.security.cert.CertificateFactory;

// import java.net.HttpURLConnection;
// import java.net.URL;

// import java.io.InputStream;
// import java.io.InputStreamReader;
// import java.io.BufferedReader;
// import java.io.ByteArrayInputStream;
// import java.util.*;

// public class Tester {

//     public static List<X509Certificate> getX509CertChainFromJWK(JWK jwk) throws CertificateException {
//         if (jwk instanceof RSAKey) {
//             RSAKey rsaKey = (RSAKey) jwk;
//             List<Base64> base64CertList = rsaKey.getX509CertChain();
//             List<X509Certificate> x509CertChain = new ArrayList<>();

//             if (base64CertList != null && !base64CertList.isEmpty()) {
//                 CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
//                 for (Base64 base64Cert : base64CertList) {
//                     byte[] certBytes = base64Cert.decode();
//                     X509Certificate x509Cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));
//                     x509CertChain.add(x509Cert);
//                 }
//                 return x509CertChain;
//             } else {
//                 throw new CertificateException("No X.509 certificate chain found in the RSA JWK.");
//             }
//         } else {
//             throw new CertificateException("Unsupported JWK type. Expecting an RSA JWK.");
//         }
//     }

//     private static HttpURLConnection createConnection(String url, String method, String requestBody, String requestId) throws IOException {
//         HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
//         conn.setRequestMethod(method);
//         conn.setDoOutput(true);
//         // conn.setRequestProperty(Constants.headerXApiKey, cfg.getApiKey());
//         conn.setRequestProperty(Constants.headerAccept, Constants.mimeApplicationJson);
//         conn.setRequestProperty(Constants.headerContentType, Constants.mimeApplicationJson);
//         conn.setRequestProperty(Constants.HeaderRequestId, requestId);

//         if (requestBody != null) {
//             conn.getOutputStream().write(requestBody.getBytes("UTF-8"));
//         }

//         return conn;
//     }

//     private static String readResponseBody(HttpURLConnection connection) throws IOException {
//         StringBuilder content = new StringBuilder();
//         try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
//             String line;
//             while ((line = reader.readLine()) != null) {
//                 content.append(line);
//             }
//         }
//         return content.toString();
//     }

//     public static X509CRL getCRL(List<String> crlArr) throws IOException {
//         if (crlArr.isEmpty()) {
//             throw new IOException("Invalid CDP count present in the certificate");
//         }

//         String crlUrl = crlArr.get(0);
//         try {
//             new URL(crlUrl).toURI();
//         } catch (Exception e) {
//             throw new IOException("Invalid CRL distribution point");
//         }

//         HttpURLConnection conn = createConnection(crlUrl, "GET", null, null);

//         try {
//             int responseCode = conn.getResponseCode();
//             if (responseCode != HttpURLConnection.HTTP_OK) {
//                 throw new IOException("HTTP error code: " + responseCode);
//             }

//             String responseBody = readResponseBody(conn);
//             String charsetName = "UTF-8";

//             // Create an InputStream from the byte array
//             InputStream inputStream = new ByteArrayInputStream(responseBody.getBytes(charsetName));

//             CertificateFactory cf = CertificateFactory.getInstance("X.509");
//             X509CRL crl = (X509CRL) cf.generateCRL(inputStream);

//             return crl;
//         } catch (Exception e) {
//             throw new IOException(e);
//         } finally {
//             conn.disconnect();
//         }
//     }

//     public static List<String> getCRLDistributionPoints(X509Certificate cert) {
//         try {
//             byte[] crlDistributionPointsExtensionValue = cert.getExtensionValue("2.5.29.31");
//             if (crlDistributionPointsExtensionValue != null) {
//                 // Extract the extension value and decode it
//                 byte[] crlDistributionPointsExtensionData = Arrays.copyOfRange(crlDistributionPointsExtensionValue, 2, crlDistributionPointsExtensionValue.length);
//                 InputStream is = new ByteArrayInputStream(crlDistributionPointsExtensionData);
//                 CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
//                 Collection<X509CRL> crls = (Collection<X509CRL>) certificateFactory.generateCRLs(is);
                
//                 List<String> crlDistributionPoints = new ArrayList<>();
                
//                 for (X509CRL crl : crls) {
//                     // Access the CRL distribution points from the CRL extension
//                     String crlDistributionPoint = crl.getIssuerX500Principal().getName();
//                     crlDistributionPoints.add(crlDistributionPoint);
//                 }
//                 return crlDistributionPoints;
//             }
//         } catch (Exception e) {
//             e.printStackTrace();
//         }
//         return null;
//     }

//     // public void verifyCRL(X509CRL crl, X509Certificate leafCert, X509Certificate caCert) throws Exception {
//     //     if (leafCert == null || caCert == null || crl == null) {
//     //         throw new Exception("Leaf Cert or CA Cert or CRL is null");
//     //     }

//     //     if (!isSignatureValid(crl, caCert)) {
//     //         throw new Exception("CRL signature verification failed");
//     //     }

//     //     Date now = new Date();
//     //     if (crl.getNextUpdate().before(now)) {
//     //         throw new Exception("Outdated CRL");
//     //     }

//     //     for (X509CRLEntry entry : crl.getRevokedCertificates()) {
//     //         if (entry.getSerialNumber().equals(leafCert.getSerialNumber())) {
//     //             throw new Exception("Certificate was Revoked");
//     //         }
//     //     }
//     // }

//     // TODO: Remove this file before release
//     // Developer friendly debug/test application
//     public static void main(String[] args) throws Exception {
//         System.out.println("Starting Tester App...");
//         String jwks = "{\"keys\":[{\"alg\":\"PS384\",\"e\":\"AQAB\",\"kid\":\"3fd751f2e0d0f52846c0ecd4972c6e99dfc642051cd339dd9b04381af8c0ddb804514a7a1fee4673ac844fd5db7f15fb\",\"kty\":\"RSA\",\"n\":\"vKKV7v7czOHapQ22ZnW677i4BkQIuxVTLk933javfZyLzpM7ZP_Mhvu9QqHrr-iKEqCDBuX1slL_hoB0fTCGGnoFTZ1lTqBdmhFysIgg5uzAqMWL2SJdzYX9RJ_ZXMFnvzTznO-b2jJd864pUI6y72mrzfTqQvgw_60fa3tjc9zjJPiqT1yadKar3G5c0fJqg7AUooTuMkIq291tHqoNhfYzzshZCSFV_d5RruheVMjvgMunx1zISiZ5RNRjcy39G7-08UTCIlSKE_GdsLDNViHqACz60BW3p-kSY5YdoslwKvDUOJnkVZMpJNfdYDoBIiIGgKL2j5H8arHmhSw1A1kl66YdDl7H5Pa46qp4B2FrS5Qpt1D9C-SZXkWN3wzDIQLsHKs0e86R5guLMS9_WcfsPCcHCLjqMZe6S-18SdjwzCK4hbn5vLCZYUzIyVEIcYT8f3mS3s3I1UxJRW53WZOEKkyGVKKGTF8uRxaksFVGrIdW0Q41Wo3mB30N2tqL\",\"x5c\":[\"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\"]}]}";
//         String jwtToken = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IjNmZDc1MWYyZTBkMGY1Mjg0NmMwZWNkNDk3MmM2ZTk5ZGZjNjQyMDUxY2QzMzlkZDliMDQzODFhZjhjMGRkYjgwNDUxNGE3YTFmZWU0NjczYWM4NDRmZDVkYjdmMTVmYiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.Mj4nQgujHiGidoRBkCzVtU6V7RAxD8PxFEpcMWkHHuLe_ZHamT1Sqnpn21JxaT6todQ3L21LAOIKzua_Zcuy-g91UCd501RqGTYQMP2EfoEZYk5uuiNmT37VpPSXSLSiRKAaNzjidpmiaoFkvNgupl8OWKJ9__4CA3W_EAw60mWcbU95ApvQz8m1VWTIGR4si7XMt1qUaPdS7Ey446W6RzU1wr9OAWhnPDLgffKH6ORYLGriBR6gAgCda1tmjMC6WtBZcqr0ub8R7_cfMn8qUsyiOjrQfyjw_3feJ5ooYqofY7Vq6YCzjvw_GSDxq5Ircbsnrm--ggK8FIJ6f6H1EEfZ-kw9Unocbew2Bul2xIM1wyyXvRtL9NDWiiGTL-IEqLqTBm5UBFuZ2VmZA1au0X1HaMDEBSWwWoE31xzGhZd3mYWpbWV7sDnJpJIIkPfHrh-J0e_aUQZfqUFp5uksBClTO7OTqrnV1F_JJXV_BhKdzj1w_esojOIuyypuR2Awr9Rbdx_mtX0gEgN-Cg8eOB46xYDVx50HWMs1HsBki3LFl0bynkpMXRcIKdc8aQDTKv3O-Wvt0PQ6Vf_F0zKy6Nms7gLGsuCSGoNbAFwAu0NkMHMwOYSbeLK7ijyLnOBPv4UDmk6h1L4HopX5OPe1o2qwCWCGpcTPWsJARKqoKx4";

//         try {

//             JWSObject jwsObject = JWSObject.parse(jwtToken);

//             Payload payload = jwsObject.getPayload();
//             String kid = jwsObject.getHeader().getKeyID();
//             if (kid == null) {
//                 throw new IllegalArgumentException("kid field missing in token header");
//             }

//             // Parse the JWKSet string
//             JWKSet jwkSet = JWKSet.parse(jwks);

//             JWK jwkKey = jwkSet.getKeyByKeyId(kid);
//             if (jwkKey == null) {
//                 throw new IllegalArgumentException("Could not find Key matching the key id");
//             }

//             int AtsCertChainMaxLen = 10;
//             List<X509Certificate> atsCerts = getX509CertChainFromJWK(jwkKey);
//             if (atsCerts.size() > AtsCertChainMaxLen) {
//                 throw new IllegalArgumentException("Token Signing Cert chain has more than " + AtsCertChainMaxLen + " certificates");
//             }

//             List<X509Certificate> rootCerts = new LinkedList<>();
//             List<X509Certificate> intermediateCerts = new LinkedList<>();
//             X509Certificate leafCert = null;

//             for (X509Certificate atsCert : atsCerts) {
//                 if (atsCert.getBasicConstraints() > -1 && atsCert.getSubjectDN().getName().contains("Root CA")) {
//                     rootCerts.add(atsCert);
//                 } else if (atsCert.getSubjectDN().getName().contains("Signing CA")) {
//                     intermediateCerts.add(atsCert);
//                 } else {
//                     leafCert = atsCert;
//                 }
//             }

            
            
            
//             X509CRL rootCrl = getCRL(getCRLDistributionPoints(intermediateCerts.get(0)));
//             // if (!verifyCRL(rootCrl, intermediateCerts.get(0), rootCerts.get(0))) {
//             //     throw new IllegalArgumentException("Failed to check ATS CA Certificate against Root CA CRL");
//             // }
            
//             X509CRL atsCrl = getCRL(getCRLDistributionPoints(leafCert));
//             // if (!verifyCRL(atsCrl, leafCert, intermediateCerts.get(0))) {
//             //     throw new IllegalArgumentException("Failed to check ATS Leaf certificate against ATS CRL");
//             // }

//             // String certificatePath = "C:\\Users\\user1\\Desktop\\test.cer";

//             // CertificateFactory cf = CertificateFactory.getInstance("X509");

//             // X509Certificate certificate = null;
//             // X509CRLEntry revokedCertificate = null;
//             // X509CRL crl = null;

//             // certificate = (X509Certificate) cf.generateCertificate(new FileInputStream(new File(certificatePath)));

//             // URL url = new URL("http://<someUrl from certificate>.crl");
//             // URLConnection connection = url.openConnection();

//             // try(DataInputStream inStream = new DataInputStream(connection.getInputStream())){

//             //     crl = (X509CRL)cf.generateCRL(inStream);
//             // }

//             // revokedCertificate = crl.getRevokedCertificate(certificate.getSerialNumber());

//             // if(revokedCertificate !=null){
//             //     System.out.println("Revoked");
//             // }
//             // else{
//             //     System.out.println("Valid");
//             // }

//             // try {
//             //     // Get the CRL distribution points extension from the certificate
//             //     byte[] crlDistributionPointExtensionValue = intermediateCerts.get(0).getExtensionValue("2.5.29.31");

//             //     System.out.println(""+ crlDistributionPointExtensionValue.toString());
                
//             //     // if (crlDistributionPointExtensionValue != null) {
//             //     //     // Use a CertificateFactory to create an X509CRL object
//             //     //     CertificateFactory cf = CertificateFactory.getInstance("X.509");
//             //     //     X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlDistributionPointExtensionValue));
                    
//             //     //     // You now have the X509CRL object for the certificate's CRL distribution points
//             //     //     // You can work with the X509CRL object as needed
//             //     // }
//             //     X509CRL rootCrl = getCRL(crlDistributionPointExtensionValue.toString());
//             // } catch (Exception e) {
//             //     e.printStackTrace(); // Handle exceptions appropriately
//             // }
            
//             // String rootCrlDistributionPoints = intermediateCerts.get(0).getCRLDistributionPoints()[0].toString();
            

//             // Add more claim extraction as needed
//         } catch (Exception e) {
//             e.printStackTrace();
//         }
//     }
// }
