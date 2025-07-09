package com.talentstream.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*; 
import com.talentstream.dto.CompanyProfileDTO;
import com.talentstream.service.CompanyProfileService;
import java.util.*;

import javax.validation.Valid;

import com.talentstream.exception.CustomException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
@RestController
@RequestMapping("/companyprofile")
public class CompanyProfileController {
	private static final Logger logger = LoggerFactory.getLogger(CompanyProfileController.class);
	 @Autowired
	    private final CompanyProfileService companyProfileService;

	 
	    @Autowired
	    public CompanyProfileController(CompanyProfileService companyProfileService) {
	        this.companyProfileService = companyProfileService;
	    }
	 
	    
	    @PostMapping("/recruiters/company-profiles/{jobRecruiterId}")
	    public ResponseEntity<String> createCompanyProfile(@Valid @RequestBody CompanyProfileDTO companyProfileDTO, BindingResult bindingResult, @PathVariable Long jobRecruiterId) {
	    	if (bindingResult.hasErrors()) {
	            // Handle validation errors
	    		Map<String, String> fieldErrors = new LinkedHashMap<>();
	    		bindingResult.getFieldErrors().forEach(fieldError -> {
	                String fieldName = fieldError.getField();
	                String errorMessage = fieldError.getDefaultMessage();
 
	                // Append each field and its error message on a new line
	                fieldErrors.merge(fieldName, errorMessage, (existingMessage, newMessage) -> existingMessage + "\n" + newMessage);
	            });
 
	            // Construct the response body with each field and its error message on separate lines
	            StringBuilder responseBody = new StringBuilder();
	            fieldErrors.forEach((fieldName, errorMessage) -> responseBody.append(fieldName).append(": ").append(errorMessage).append("\n"));
 
	            return ResponseEntity.badRequest().body(responseBody.toString());
	        }
	    	
	    	try {
	    		
	           companyProfileService.saveCompanyProfile(companyProfileDTO,jobRecruiterId);
	           logger.info("Company profile saved successfully for job recruiter ID: {}", jobRecruiterId);
	           return ResponseEntity.status(HttpStatus.OK).body("CompanyProfile saved successfully");
	        } catch (CustomException ce) {
	        	 logger.error("Error occurred while saving company profile for job recruiter ID: {}", jobRecruiterId, ce);
	            return ResponseEntity.status(ce.getStatus()).body(ce.getMessage());
	        } catch (Exception e) {
	        	 logger.error("Internal server error occurred while saving company profile for job recruiter ID: {}", jobRecruiterId, e);
	            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal server error occurred.");
	        }
	    }
	 
	    @PutMapping("/{jobRecruiterId}/update-approval-status")
	    public ResponseEntity<String> updateApprovalStatus(
	            @PathVariable Long jobRecruiterId,
	            @RequestParam String newStatus) {
	        try {
	            String message = companyProfileService.updateApprovalStatus(jobRecruiterId, newStatus);
	            logger.info("Approval status updated successfully for job recruiter ID: {}", jobRecruiterId);
	            return ResponseEntity.status(HttpStatus.OK).body(message);
	        } catch (CustomException ce) {
	        	 logger.error("Error occurred while updating approval status for job recruiter ID: {}", jobRecruiterId, ce);
	            return ResponseEntity.status(ce.getStatus()).body(ce.getMessage());
	        } catch (Exception e) {
	        	  logger.error("Internal server error occurred while updating approval status for job recruiter ID: {}", jobRecruiterId, e);
	            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal server error occurred.");
	        }
	    }
	    @GetMapping("/recruiters/getCompanyProfile/{id}")
	    public ResponseEntity<CompanyProfileDTO> getCompanyProfileById(@PathVariable Long id) {
	    	try {
	    		 Optional<CompanyProfileDTO> companyProfileDTO = companyProfileService.getCompanyProfileById(id);
	             return companyProfileDTO.map(profile -> {
	                 logger.info("Company profile retrieved successfully for ID: {}", id);
	                 return new ResponseEntity<>(profile, HttpStatus.OK);
	             }).orElseGet(() -> {
	                 logger.warn("Company profile not found for ID: {}", id);
	                 return new ResponseEntity<>(HttpStatus.NOT_FOUND);
	             });
	        } catch (CustomException ce) {
	        	 logger.error("Error occurred while retrieving company profile for ID: {}", id, ce);
	            return ResponseEntity.status(ce.getStatus()).body(null);
	        } catch (Exception e) {
	        	logger.error("Internal server error occurred while retrieving company profile for ID: {}", id, e);
	            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
	        }
	    }
	    
	    @GetMapping("/recruiter/getCompanyProfile/{jobRecruiterId}")
	    public ResponseEntity<CompanyProfileDTO> getCompanyProfileByRecruiterId(@PathVariable Long jobRecruiterId ){
	    	try {
	    		 Optional<CompanyProfileDTO> companyProfileDTO = companyProfileService.getCompanyProfileDetailsByRecruiterId(jobRecruiterId);
	             return companyProfileDTO.map(profile -> {
	                 logger.info("Company profile retrieved successfully for RecruiterID: {}", jobRecruiterId);
	                 return new ResponseEntity<>(profile, HttpStatus.OK);
	             }).orElseGet(() -> {
	                 logger.info("Company profile not found for RecruiterID: {}", jobRecruiterId);
	                 return new ResponseEntity<>(HttpStatus.NOT_FOUND);
	             });
	        } catch (CustomException ce) {
	        	 logger.info("Error occurred while retrieving company profile for RecruiterID: {}", jobRecruiterId, ce);
	            return ResponseEntity.status(ce.getStatus()).body(null);
	        } catch (Exception e) {
	        	logger.info("Internal server error occurred while retrieving company profile for RecruiterID: {}", jobRecruiterId, e);
	            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
	        }
	    }
	    
	    @PutMapping("/companyprofile/update-companyprofile/{jobRecruiterId}")
	    public ResponseEntity<String> updateCompanyProfile(@PathVariable Long jobRecruiterId, @Valid @RequestBody CompanyProfileDTO companyProfileDTO, BindingResult bindingResult ){
	    	if (bindingResult.hasErrors()) {
	            // Handle validation errors
	    		Map<String, String> fieldErrors = new LinkedHashMap<>();
	    		bindingResult.getFieldErrors().forEach(fieldError -> {
	                String fieldName = fieldError.getField();
	                String errorMessage = fieldError.getDefaultMessage();
 
	                // Append each field and its error message on a new line
	                fieldErrors.merge(fieldName, errorMessage, (existingMessage, newMessage) -> existingMessage + "\n" + newMessage);
	            });
 
	            // Construct the response body with each field and its error message on separate lines
	            StringBuilder responseBody = new StringBuilder();
	            fieldErrors.forEach((fieldName, errorMessage) -> responseBody.append(fieldName).append(": ").append(errorMessage).append("\n"));
 
	            return ResponseEntity.badRequest().body(responseBody.toString());
	        }
	    	
	    	try {
	    		
	           companyProfileService.updateCompanyDetails(companyProfileDTO,jobRecruiterId);
	           logger.info("Company profile updated successfully for job recruiter ID: {}", jobRecruiterId);
	           return ResponseEntity.status(HttpStatus.OK).body("CompanyProfile updated successfully");
	        } catch (CustomException ce) {
	        	 logger.error("Error occurred while updating company profile details for job recruiter ID: {}", jobRecruiterId, ce);
	            return ResponseEntity.status(ce.getStatus()).body(ce.getMessage());
	        } catch (Exception e) {
	        	 logger.error("Internal server error occurred while updating company profile for job recruiter ID: {}", jobRecruiterId, e);
	            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal server error occurred.");
	        }
	    }
	    	
	    
	    @GetMapping("/companyprofile/approval-status/{jobRecruiterId}")
	    public ResponseEntity<String> checkApprovalStatus(@PathVariable Long jobRecruiterId) {
	        try {
	            String approvalStatus = companyProfileService.checkApprovalStatus(jobRecruiterId);
	            logger.info("Approval status checked successfully for job recruiter ID: {}", jobRecruiterId);
	            return ResponseEntity.status(HttpStatus.OK).body(approvalStatus);
	        } catch (CustomException ce) {
	        	  logger.error("Error occurred while checking approval status for job recruiter ID: {}", jobRecruiterId, ce);
	            return ResponseEntity.status(ce.getStatus()).body(ce.getMessage());
	        } catch (Exception e) {
	        	logger.error("Internal server error occurred while checking approval status for job recruiter ID: {}", jobRecruiterId, e);
	            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal server error.");
	        }
	    }


    
}

