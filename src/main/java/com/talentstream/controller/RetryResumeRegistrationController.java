package com.talentstream.controller;

import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.talentstream.entity.Applicant;
import com.talentstream.repository.RegisterRepository;
import com.talentstream.dto.ResumeRegisterDto;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestTemplate;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

@RestController
@RequestMapping("/resume")
public class RetryResumeRegistrationController {

	 @Autowired
	 private RegisterRepository applicantRepository;
	 
	 @Autowired
	 private RestTemplate restTemplate;
	 
	@PostMapping("/retryResumeRegistration")
	public ResponseEntity<String> retryResumeRegistration() {
	    try {
	        
			// Get applicants where resume_id is 'Not available'
	        List<Applicant> failedApplicants = applicantRepository.findAllByResumeId("Not available");
	        System.out.println("checking for size "+failedApplicants.size());
	        for (Applicant applicant : failedApplicants) {
	        	
	            // Prepare resume registration data
	            ResumeRegisterDto resume = new ResumeRegisterDto();
	         
	            String randomString = UUID.randomUUID().toString().replaceAll("[^a-z0-9._-]", "").substring(0, 10);
	            resume.setName("resume");
	            String username = "resume"+randomString;
	            resume.setUsername(username);
	            resume.setEmail(applicant.getEmail().toLowerCase());
	            resume.setPassword(applicant.getPassword());
	            resume.setLocale("en-US");
	            
	            // Set headers
	            HttpHeaders headers = new HttpHeaders();
	            headers.setContentType(MediaType.APPLICATION_JSON);

	            // Create request
	            HttpEntity<ResumeRegisterDto> requestEntity = new HttpEntity<>(resume, headers);

	            // Define the endpoint URL
	            String resumeRegisterUrl = "https://resume.bitlabs.in:5173/api/auth/register";

	            try {
	                // Make POST request to the resume service
	            	
	                ResponseEntity<String> response = restTemplate.postForEntity(resumeRegisterUrl, requestEntity, String.class);
	               
	                // Parse the response
	                Gson gson = new Gson();
	                JsonObject jsonResponse = gson.fromJson(response.getBody(), JsonObject.class);
	                String userId = jsonResponse.getAsJsonObject("user").get("id").getAsString();
                    System.out.println("resume id  "+userId);
	                // Update the applicant with the resume ID
	                applicant.setResumeId(userId);
	                applicantRepository.save(applicant);
	                System.out.println("resume id  "+userId+"  saved in TS db"); 
	            } catch (Exception e) {
	                System.out.println("Error registering applicant " + applicant.getEmail() + ": " + e.getMessage());
	            }
	        }
	        return ResponseEntity.ok("Retry for resume registration completed.");
	    } catch (Exception e) {
	        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error retrying resume registration");
	    }
	}

}
