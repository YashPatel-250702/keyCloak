package com.talentstream.controller;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.data.domain.Pageable;
import org.modelmapper.ModelMapper;
import com.talentstream.dto.JobDTO;
import com.talentstream.entity.Job;
import com.talentstream.service.SearchForaJobService;
import com.talentstream.exception.CustomException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
@RestController
@RequestMapping("/searchjob")
public class SearchForaJobController {
    final ModelMapper modelMapper = new ModelMapper();
	@Autowired
    private SearchForaJobService jobSearchService;
	private static final Logger logger = LoggerFactory.getLogger(ApplicantProfileController.class);
    
	
	@GetMapping("/applicant/searchjobbyskillname/{applicantId}/jobs/{skillName}")
    public ResponseEntity<Page<JobDTO>> searchJobsBySkillAndApplicant(
    		@PathVariable int applicantId,
            @PathVariable String skillName,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "5") int size
    ) {
    	
   
    	try {
            Pageable pageable = PageRequest.of(page, size);
            Page<Job> jobs = jobSearchService.searchJobsBySkillAndApplicant(applicantId, skillName, pageable);

            if (jobs.isEmpty()) {
                return ResponseEntity.noContent().build();
            }

          Page<JobDTO> jobsDTO = jobs.map(job -> {
                JobDTO jobDTO = modelMapper.map(job, JobDTO.class);
                jobDTO.setCompanyname(job.getJobRecruiter().getCompanyname());
                jobDTO.setMobilenumber(job.getJobRecruiter().getMobilenumber());
                jobDTO.setEmail(job.getJobRecruiter().getEmail());
                return jobDTO;
            });
            return ResponseEntity.ok(jobsDTO);
        } catch (CustomException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}
