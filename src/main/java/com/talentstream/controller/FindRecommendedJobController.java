package com.talentstream.controller;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.talentstream.dto.GetJobDTO;
import com.talentstream.exception.CustomException;
import com.talentstream.repository.ApplicantProfileRepository;
import com.talentstream.service.CompanyLogoService;
import com.talentstream.service.FinRecommendedJobService;

@RestController
@RequestMapping("/recommendedjob")
public class FindRecommendedJobController {
    private final FinRecommendedJobService finJobService;
    @Autowired
    private CompanyLogoService companyLogoService;
    private static final Logger logger = LoggerFactory.getLogger(FindRecommendedJobController.class);

    @Autowired
    private ApplicantProfileRepository applicantRepository;

    @Autowired
    public FindRecommendedJobController(FinRecommendedJobService finJobService) {
        this.finJobService = finJobService;
    }

    @GetMapping("/findrecommendedjob/{applicantId}")
    public ResponseEntity<List<GetJobDTO>> recommendJobsForApplicant(
            @PathVariable String applicantId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "16") int size) {
        try {
            long applicantIdLong = Long.parseLong(applicantId);
            List<GetJobDTO> recommendedJobs = finJobService.recommendJobsForApplicant(applicantIdLong, page, size);
 
            if (!recommendedJobs.isEmpty()) {
                return ResponseEntity.ok(recommendedJobs);
 
            } else {
                // #change
                // return
                // ResponseEntity.status(HttpStatus.NOT_FOUND).body(Collections.emptyList());
                return ResponseEntity.notFound().build();
 
            }
 
        } catch (NumberFormatException ex) {
 
            logger.error("Invalid applicant ID format: {}", applicantId, ex);
            throw new CustomException("Invalid applicant ID format", HttpStatus.BAD_REQUEST);
        } catch (CustomException ce) {
 
            logger.error("Custom exception occurred: {}", ce.getMessage());
            return ResponseEntity.status(ce.getStatus()).body(Collections.emptyList());
        } catch (Exception e) {
 
            logger.error("Error occurred while processing request", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Collections.emptyList());
        }
    }
 
 
  
    @GetMapping("/countRecommendedJobsForApplicant/{applicantId}")
    public long countRecommendedJobsForApplicant(@PathVariable long applicantId) {
        logger.info("Count of recommended jobs for applicant {} retrieved successfully: {}");
        return finJobService.countRecommendedJobsForApplicant(applicantId);
    }

}
