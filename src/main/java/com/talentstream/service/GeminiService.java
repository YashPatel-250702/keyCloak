package com.talentstream.service;

import com.talentstream.AwsSecretsManagerUtil;
import com.talentstream.entity.GeminiRequest;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

@Service
public class GeminiService {

    private static final Logger logger = LoggerFactory.getLogger(GeminiService.class);

    @Autowired
    private AwsSecretsManagerUtil secretsManagerUtil;

    public ResponseEntity<String> chatWithGemini(GeminiRequest request) {
        logger.info("Inside chatWithGemini service method");

        try {
            String geminiApiKey = loadCredentials();
            if (geminiApiKey == null || geminiApiKey.isEmpty()) {
                logger.error("GEMINI_API_KEY is null or empty");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("GEMINI_API_KEY not available");
            }

            String url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key="
                    + geminiApiKey;

            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<GeminiRequest> entity = new HttpEntity<>(request, headers);
            logger.info("Sending request to Gemini API");

            ResponseEntity<String> response = restTemplate.postForEntity(url, entity, String.class);
            logger.info("Received response from Gemini API: {}", response.getStatusCode());

            return ResponseEntity.ok(response.getBody());

        } catch (HttpClientErrorException e) {
            logger.error("HTTP error while calling Gemini API: {}", e.getMessage());
            return ResponseEntity.status(e.getStatusCode()).body("Gemini API Error: " + e.getResponseBodyAsString());
        } catch (Exception e) {
            logger.error("Unexpected error: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal Server Error");
        }
    }

    private String loadCredentials() {
        logger.info("Inside loadCredentials()");

        try {
            String secretJson = secretsManagerUtil.getSecret();

            if (secretJson == null || secretJson.isEmpty()) {
                logger.error("Secret is null or empty");
                return null;
            }

            JSONObject credentials = new JSONObject(secretJson);

            if (!credentials.has("GEMINI_API_KEY")) {
                logger.error("GEMINI_API_KEY not present in secret");
                return null;
            }

            String key = credentials.getString("GEMINI_API_KEY");
            logger.info("GEMINI_API_KEY successfully loaded");
            return key;

        } catch (Exception e) {
            logger.error("Exception while loading GEMINI_API_KEY: {}", e.getMessage(), e);
            return null;
        }
    }
}
