package com.talentstream.controller;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.talentstream.dto.GetJobDTO;
import com.talentstream.exception.CustomException;
import com.talentstream.service.CompanyLogoService;
import com.talentstream.service.SavedJobService;

@RestController
@RequestMapping("/savedjob")
public class SavedJobController {
    final ModelMapper modelMapper = new ModelMapper();
    @Autowired
    private SavedJobService savedJobService;
    @Autowired
    private CompanyLogoService companyLogoService;
    private static final Logger logger = LoggerFactory.getLogger(ApplicantProfileController.class);

    @PostMapping("/applicants/savejob/{applicantId}/{jobId}")
    public ResponseEntity<String> saveJobForApplicant(
            @PathVariable long applicantId,
            @PathVariable long jobId) {
        try {
            savedJobService.saveJobForApplicant(applicantId, jobId);
            return ResponseEntity.ok("Job saved successfully for the applicant.");
        } catch (CustomException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error saving job for the applicant.");
        }
    }

    @GetMapping("/getSavedJobs/{applicantId}")
    public ResponseEntity<List<GetJobDTO>> getSavedJobsForApplicantAndJob(
            @PathVariable long applicantId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        try {
            Page<GetJobDTO> savedJobsPage = savedJobService.getSavedJobsForApplicant(applicantId, page, size);
 
            if (savedJobsPage.isEmpty()) {
                return ResponseEntity.noContent().build();
            }
 
            List<GetJobDTO> savedJobsDTOList = savedJobsPage.stream().map(job -> {
            	GetJobDTO jobDTO = modelMapper.map(job, GetJobDTO.class);               
                return jobDTO;
            }).collect(Collectors.toList()); // Convert stream to list
 
            return ResponseEntity.ok(savedJobsDTOList);
        } catch (CustomException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Collections.emptyList());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Collections.emptyList());
        }
    }
     @GetMapping("/countSavedJobs/{applicantId}")
    public ResponseEntity<?> countSavedJobsForApplicant(@PathVariable long applicantId) {
        try {
            long count = savedJobService.countSavedJobsForApplicant(applicantId);
            return ResponseEntity.ok(count);
        } catch (CustomException e) {
            return ResponseEntity.status(e.getStatus()).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An unexpected error occurred.");
        }
    }

    @DeleteMapping("/applicants/deletejob/{applicantId}/{jobId}")
    public ResponseEntity<Object> deleteSavedJobForApplicant(@PathVariable long applicantId, @PathVariable long jobId) {
        try {
            int deleteSavedJobForApplicant = savedJobService.deleteSavedJobForApplicant(applicantId, jobId);

            if (deleteSavedJobForApplicant <= 0) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body("Job Not saved with jobIdn : " + jobId + " and Applicant Id : " + applicantId);
            }
            return ResponseEntity.status(HttpStatus.OK).body("Saved job deleted successfully from database");

        } catch (CustomException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error deleting saved job for the applicant.");
        }

    }

}
