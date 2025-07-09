package com.talentstream.healthcheck;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class HealthCheckService {
 
    private final RestTemplate restTemplate;
 
    @Autowired
    public HealthCheckService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }
 
    public boolean isBackendHealthy() {
        try {
            // Replace the URL with your actual health check endpoint
            String healthCheckUrl = "http://localhost:8081/health";
            String result = restTemplate.getForObject(healthCheckUrl, String.class);
 
            // Customize this condition based on the expected response from your health check
            return result != null && result.contains("Server is up and running");
        } catch (Exception e) {
            // Log or handle any exceptions that may occur during the health check
            e.printStackTrace();
            return false;
        }
    }
}