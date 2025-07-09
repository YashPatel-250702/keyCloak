package com.talentstream.service;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import com.talentstream.AwsSecretsManagerUtil;
import java.util.Map;

@Service
public class ZohoAuthService {

    @Autowired
    private AwsSecretsManagerUtil secretsManagerUtil;
    private final Logger logger = LoggerFactory.getLogger(ZohoAuthService.class);

    private static final String TOKEN_URL = "https://accounts.zoho.com/oauth/v2/token";
//    private static final String clientId = "1000.Z4COZTHBLAIUU28RXXVKFVMX8F0U0H";
//    private static final String clientSecret = "fcdfb51f30d3beef6c7eba8639a293fc4b34f822b0";
//    private static final String refreshToken = "1000.bd4f7d5661510c9bd7e167a863f154aa.09b8d18ca8c641c1d7fe6c8078b92d14";
  
    private String clientId;
    private String clientSecret;
    private String refreshToken;
    private String accessToken;
    private long expiryTime; // Stores token expiry time
//
//    /**
//     * ✅ Fetch Zoho OAuth credentials from AWS Secrets Manager and initialize variables.
//     */
    private void loadCredentials() {
        JSONObject credentials = new JSONObject(secretsManagerUtil.getSecret());
        clientId = credentials.getString("ZOHO_CLIENT_ID");
        clientSecret = credentials.getString("ZOHO_CLIENT_SECRET");
        refreshToken = credentials.getString("ZOHO_REFRESH_TOKEN");
    }

    /**
     * ✅ Retrieve a valid access token (refresh if expired)
     */
    public String getAccessToken() {
        if (accessToken == null || System.currentTimeMillis() >= expiryTime) {
            logger.info("Access Token is null or expired. Refreshing...");
            refreshAccessToken();  
        }
        logger.info("Access Token at getAccessToken(): " + accessToken);
        return accessToken;
    }
 

    /**
     * ✅ Check if the access token has expired
     */
    private boolean isAccessTokenExpired() {
        return System.currentTimeMillis() >= expiryTime;
    }

    /**
     * ✅ Refresh access token using Zoho OAuth
     */
    public void refreshAccessToken() {
        // Ensure credentials are loaded
        if (clientId == null || clientSecret == null || refreshToken == null) {
            logger.info("Credentials are null. Loading...");
            loadCredentials();
        }

        RestTemplate restTemplate = new RestTemplate();
        String requestUrl = TOKEN_URL +
                "?refresh_token=" + refreshToken +
                "&client_id=" + clientId +
                "&client_secret=" + clientSecret +
                "&grant_type=refresh_token";
        ResponseEntity<Map> response = restTemplate.postForEntity(requestUrl, null, Map.class);
 
        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
            accessToken = (String) response.getBody().get("access_token");
 
            
            Object expiresInObj = response.getBody().get("expires_in");
            long expiresIn = expiresInObj instanceof Number ? ((Number) expiresInObj).longValue() : 3600;
 
            expiryTime = System.currentTimeMillis() + (expiresIn * 1000);
 
            logger.info("Access token: {}, Token expires in: {}" , accessToken, expiresIn);
        } else {
            logger.error("Failed to refresh token: " + response.getBody());
        }
    }
    
    
}
