package com.talentstream.service;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import com.talentstream.exception.CustomException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import com.talentstream.entity.ApplicantProfile;
import com.talentstream.entity.Job;
import com.talentstream.repository.ApplicantProfileRepository;
import com.talentstream.repository.JobRepository;

@Service
public class SearchForaJobService {
	@Autowired
    private ApplicantProfileRepository applicantProfileRepository;

    @Autowired
    private JobRepository jobRepository;

    public Page<Job> searchJobsBySkillAndApplicant(int applicantId, String skillName, Pageable pageable) {
    	 try {
             Optional<ApplicantProfile> applicantOptional = applicantProfileRepository.findById(applicantId);

             if (applicantOptional.isPresent()) {
                 return jobRepository.findJobsBySkillName(skillName, pageable);
             } else {
                 throw new CustomException("Applicant not found",HttpStatus.INTERNAL_SERVER_ERROR);
             }
         } catch (Exception e) {
             throw new CustomException("Error searching jobs by skill for the applicant", HttpStatus.INTERNAL_SERVER_ERROR);
         }
     }
}
