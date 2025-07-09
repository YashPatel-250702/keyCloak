package com.talentstream.service;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
 
@Service
public class ZohoCRMService {
 
    private final ZohoAuthService zohoAuthService;
    private static final String ZOHO_LEADS_URL = "https://www.zohoapis.com/crm/v7/Leads";
    private final Logger logger = LoggerFactory.getLogger(ZohoCRMService.class);
 
    public ZohoCRMService(ZohoAuthService authService) {
        this.zohoAuthService = authService;
    }
 
    public String getLeads() {
        String accessToken = zohoAuthService.getAccessToken();
        RestTemplate restTemplate = new RestTemplate();
 
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);
 
        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(ZOHO_LEADS_URL, HttpMethod.GET, entity, String.class);
 
        return response.getBody();
    }
    public Object storeDataInZohoCRM(Map<String, Object> requestData) {
        String accessToken = zohoAuthService.getAccessToken();
        RestTemplate restTemplate = new RestTemplate();
 
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " +accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);
 
        HttpEntity<Map<String, Object>> request = new HttpEntity<>(requestData, headers);
        logger.info("Request: " + request);
        ResponseEntity<Object> response = restTemplate.exchange(ZOHO_LEADS_URL, HttpMethod.POST, request, Object.class);
 
        return response.getBody();
    }
    public Object updateLead(String recordId, Map<String, Object> updateData) {
        String accessToken = zohoAuthService.getAccessToken();
        RestTemplate restTemplate = new RestTemplate();
 
        String updateUrl = ZOHO_LEADS_URL + "/" + recordId;
 
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);
 
        HttpEntity<Map<String, Object>> request = new HttpEntity<>(updateData, headers);
        ResponseEntity<Object> response = restTemplate.exchange(updateUrl, HttpMethod.PUT, request, Object.class);
 
        return response.getBody();
    }

    public Object deleteLead(String recordId) {
    	String accessToken = zohoAuthService.getAccessToken();
        RestTemplate restTemplate = new RestTemplate();
 
        String deleteUrl = ZOHO_LEADS_URL + "/" +recordId;
 
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<Object> response = restTemplate.exchange(deleteUrl, HttpMethod.DELETE, entity, Object.class);
        return response.getBody();
    }
    public Object searchLeadByEmail(String email) {
    	String accessToken = zohoAuthService.getAccessToken();
        RestTemplate restTemplate = new RestTemplate();
 
        String deleteUrl = ZOHO_LEADS_URL + "/search?email=" +email;
 
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<Object> response = restTemplate.exchange(deleteUrl, HttpMethod.GET, entity, Object.class);
        return response.getBody();
    }

}