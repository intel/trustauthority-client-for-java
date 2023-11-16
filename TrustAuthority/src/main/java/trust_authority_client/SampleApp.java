package trust_authority_client;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import io.jsonwebtoken.Jws;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;

import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SampleApp {

    // private static final Logger logger = LogManager.getLogger(SampleApp.class);

    public static void main(String[] args) throws Exception {
        System.out.println("Starting Sample App...");

        // Setting default arguments in case BaseURL, apiURL and apiKey are not provided
        String BaseURL = "http://localhost:8080";
        String apiURL = "http://localhost:8080";
        String apiKey = "";

        System.out.println("Number of arguments: " + args.length);

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
        TrustAuthorityConnector connector = new TrustAuthorityConnector(cfg, "", "", "");

        // Testing attest API - internally tests GetNonce(), collectEvidence() and GetToken() API
        AttestArgs attestArgs = new AttestArgs();
        attestArgs.setRequestId("abcd1234");
        AttestResponse response = connector.attest(attestArgs);
        
        // Receive response from Server
        System.out.println("Received token" + response.getToken());

        String token = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IjNmZDc1MWYyZTBkMGY1Mjg0NmMwZWNkNDk3MmM2ZTk5ZGZjNjQyMDUxY2QzMzlkZDliMDQzODFhZjhjMGRkYjgwNDUxNGE3YTFmZWU0NjczYWM4NDRmZDVkYjdmMTVmYiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.Mj4nQgujHiGidoRBkCzVtU6V7RAxD8PxFEpcMWkHHuLe_ZHamT1Sqnpn21JxaT6todQ3L21LAOIKzua_Zcuy-g91UCd501RqGTYQMP2EfoEZYk5uuiNmT37VpPSXSLSiRKAaNzjidpmiaoFkvNgupl8OWKJ9__4CA3W_EAw60mWcbU95ApvQz8m1VWTIGR4si7XMt1qUaPdS7Ey446W6RzU1wr9OAWhnPDLgffKH6ORYLGriBR6gAgCda1tmjMC6WtBZcqr0ub8R7_cfMn8qUsyiOjrQfyjw_3feJ5ooYqofY7Vq6YCzjvw_GSDxq5Ircbsnrm--ggK8FIJ6f6H1EEfZ-kw9Unocbew2Bul2xIM1wyyXvRtL9NDWiiGTL-IEqLqTBm5UBFuZ2VmZA1au0X1HaMDEBSWwWoE31xzGhZd3mYWpbWV7sDnJpJIIkPfHrh-J0e_aUQZfqUFp5uksBClTO7OTqrnV1F_JJXV_BhKdzj1w_esojOIuyypuR2Awr9Rbdx_mtX0gEgN-Cg8eOB46xYDVx50HWMs1HsBki3LFl0bynkpMXRcIKdc8aQDTKv3O-Wvt0PQ6Vf_F0zKy6Nms7gLGsuCSGoNbAFwAu0NkMHMwOYSbeLK7ijyLnOBPv4UDmk6h1L4HopX5OPe1o2qwCWCGpcTPWsJARKqoKx4";
	    String tokenInvalid = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IjNmZDc1MWYyZTBkMGY1Mjg0NmMwZWNkNDk3MmM2ZTk5ZGZjNjQyMDUxY2QzMzlkZDliMDQzODFhZjhjMGRkYjgwNDUxNGE3YTFmZWU0NjczYWM4NDRmZDVkYjdmMTVmYiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tJPT6hz2psdkB2yuf17UjqcH1t4ujt9iwRP8iFrG93vMZN2W8umIlYVCE9NVigYoX3EkNuOq_OGlYvfdrUjsYFU-hFLvmORLbaBZ2u0GCfxgrGpYX7ngjZRad_cE9KGcmv6R2fxWI4gF-73DMeaoGWXTVAPlquV_Tyc987zeXj1KXAVO0SDWG68LiWVcl42FUlOI_2mXV4rGsgWLPgbyaa5SuSu-ENreQenvyUMMzdntbJtytQycOxYVrppQJaFNKwn8OfwloGvt7jedylCZgU1MBIrTXUN_lgKAZnFfRxUMfbiV-i73kPqWcOAxbzK8JZPAKv4AyVDWFEBhKKuxiQ";
        String tokenMissingKID = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.IO_z9EOfF9e2noXDva33D8D2y9CS8Tf9lmB-w7cK5DNawk0r66RrjmY-jk6p8MIha126nniMRI7UZaeSSrfzwwuYVZCD35X7xRqhsRz5mpVkoluooXENIVvE4F8UVpY4yewgB6JXvFFplqaXWCSoQ8GxmwHXnHwEzS_W0df5VqTTBilRtgEEbwqBnANWWVkzm89ZX9d2ebkgow5dG9O-ra0SNhO_-66a4b78wvhiE_dw-99pnYbU-XLUwqVEu1Nk4sMW9jp7Y7d0f_WR9uOcB4SvojVJBTGc9cuCBjDI8g2zYyFs04exifYF7SQiofn1KodR5FDwOUiNwQfC-isnwa9fpKPOuGXEOJm6FBCK7cYrpP0JQrOv3IVeIh1Qix3N6-sF_TfUWgzBZlolvaf98msky8Yv0udyL0rkKMUUStV48R4TTChuAtpxoSu1Fr-sdMhWf76xGHvXjTUL_W4TZA8a3GyxLHawbcXez-Sk357djVol5xDIVAZU3ORpT4RuwPBKaoodEBSSWnFlP0l577Y7J8St0_UdGCyg8TMt2MBjaah1EJRDLOiXw_C0_Efa0rid6HbKlzwhlk6BzXQbnxdRoFBnh2KcsewQMMKfVtv3_nFxvgyiMTgdXY1lbmmVJ9rmEJlVyzCdfLoZavSrBwl5xkGipr657fmZ2Tbe6j0";
        String tokenInvalidKID = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6MTIzNH0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.lsBarFSfZNLtmTJyKfcnxqoU80QTx2PJHU0cl4esXIi64iD0C0h_B2TobIfkcUHIDNnkwcmZmik9dMxQaKU59qW6yUPgN9GcglD6RpgrJ4StHaOpfJvWY6TtsuSdcWlG33wc9RhcZ4PXV4pdYx5210e0PRgGAPelyq0MvdZa1IpZUnssQulMrk6OJNs3L-7ZfI5ZQFmJyWMzWcY7HQ9Nk2vfjaYtChfmKCSVdbyrDjtzsSDY9r5bYMI5pUCxXl30RSiEYv8fOBpYB_TJPxHyC0VaYtYVLIl4ZzUzG5VS4ragjJVXZZkX1tcDSpTakmgMbcvT1aqyJ9iVGJKSzfPovht-HxYlnmPysQPgeYY4LMywlRW8RJned9ZmKZ4F5Y8aTAUWdO4_ruBL0u8Z7J8-BTGkvNUgBUx9c7p_uy1dt7MTQkDW7d6sjP89xoNHnz4z4w7erAEuBEaPrknmYokpIdqf-esynBtW4NfIKyfl-_PGJnngPn7ziBNuTqxzq0sgTdovX8nxwal3LeWVtXx6HzN5CIRcR7BpDNC5jRhsyZ0U-p4D9Iic63KXMQLhkMx3D0vxzpzlT_zhkvw-kqXNsp6sIN3XqwlZjNTX6lptjV_OXnpVgJ8pb5svURGbwWcFIDJlgaYkHn7jLHnnaKz1aaHQezClod6_vbEPyjcfrsI";
        String tokenWrongKID   = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.O1YS3tK9moRRMCLkqWloLHIJ_F-NfpfQVFLo4mq3ui4HCgQLAK7bELjHl__igbzF6zTOLd3fwaoCKeVF1DDwBBoPhMXkAjZQMaNBFz8xZghQZfkSJLiMygyrkzSqgzLFMOgdBJaqcKxWT-cbO3JyAmG4sbxxFo8Lh5foVCmzF88aqfX0MPvUuiQG9aNVvJFqj2gW9hTSB3ljhxeRqZhTSQcpEkE67Xpr70rcdXaLbK-Ab4gw9YrW4aMHqR1aeLWg-s1OTosRpJGKLQ90BqWUJSx1QCmzRbAsEOfUeIK2CSwD0miUw6aSR2tVQcj0peZ2T-1xr8j0UFHRGCo5iLyAGBrHuNZ5c3fPL_xygwAkGKSkaO22d0NLRjauNeMKwT16BqZvZdN050AhfkMrwPa6AxQeJC__uBiIScKWK5ZSJJP3ba0_LHCsnnAOVZJMdD0uGdvzwXLhCTT44yeGVRbmw6KvLKjwLLotEsXY6M84rtMYnP16XeenidMH0-5YoaNOkFMR987qV-q2yXRemEHdH4KzmoBnMPtlvTSi1XW4jTM7bgziPEEK44mfZC_bkHKQnEWT51whYOPgcWYwYfjBm0oMoPKeCuIbHU6tMceGqZTsAzaWUSSlti_jVmQFR6Pp22w1d7BY-TGKDDG_wK4adj4n_KoGw5_HFYwoQfb6G_o";
        JWSObject jws = connector.verifyToken(token);
    }
}