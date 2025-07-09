package com.talentstream.controller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.talentstream.service.ViewJobService;
import com.talentstream.exception.CustomException;

@RestController
@RequestMapping("/viewjob")
public class ViewJobController {
	 
	@Autowired
    private ViewJobService viewJobService;
	private static final Logger logger = LoggerFactory.getLogger(ApplicantProfileController.class); 
	   @GetMapping("/applicant/viewjob/{jobId}")
	    public ResponseEntity<?> getJobDetailsForApplicant(
	                      @PathVariable Long jobId) {
	    	
		   try {
			   ResponseEntity<?> jobDetails = viewJobService.getJobDetailsForApplicant(jobId);
		        return ResponseEntity.ok(jobDetails);
		    } catch (CustomException e) {
		        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
		    } catch (Exception e) {
		        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error retrieving job details");
		    }
	 
		   }  
	   
	   @GetMapping("/recruiter/viewjob/{jobId}")
	    public ResponseEntity<?> getJobDetailsForApplicant1(
	                      @PathVariable Long jobId) {
		   ResponseEntity<?> jobDetails = viewJobService.getJobDetailsForApplicant(jobId);
	        return ResponseEntity.ok(jobDetails);
	 
		   } 
	   
	   @GetMapping("/applicant/viewjob/{jobId}/{applicantId}")
	    public ResponseEntity<?> getJobDetailsForApplicant(
	            @PathVariable Long jobId,
	            @PathVariable Long applicantId) {
		   

	        try {
	            ResponseEntity<?> jobDetails = viewJobService.getJobDetailsForApplicant(jobId, applicantId);
	            return ResponseEntity.ok(jobDetails);
	        } catch (CustomException e) {
	            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
	        } catch (Exception e) {
	            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error retrieving job details");
	        }
	    }
}
