package com.talentstream.controller;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.talentstream.dto.JobDTO;
import com.talentstream.dto.RecuriterSkillsDTO;
import com.talentstream.entity.Job;
import com.talentstream.entity.RecuriterSkills;
import com.talentstream.service.WidgetService;

@RestController
public class Widget {

	@Autowired
	WidgetService widgetService;
	
	@GetMapping("/getAllJobs")
	public ResponseEntity<List<JobDTO>> viewAllJobs(){
		
		List<Job> jobs=widgetService.getAllJobs();
		
		if (jobs.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Collections.emptyList());
        } else {
            List<JobDTO> jobDTOs = jobs.stream()
                    .map(job -> convertEntityToDTO(job))
                    .collect(Collectors.toList());
            return ResponseEntity.ok(jobDTOs);
        }
	}
	
	private JobDTO convertEntityToDTO(Job job) {
        JobDTO jobDTO = new JobDTO();
        jobDTO.setId(job.getId());
        jobDTO.setJobTitle(job.getJobTitle());
        jobDTO.setMinimumExperience(job.getMinimumExperience());
        jobDTO.setMaximumExperience(job.getMaximumExperience());
        jobDTO.setMinSalary(job.getMinSalary());
        jobDTO.setMaxSalary(job.getMaxSalary());
        jobDTO.setLocation(job.getLocation());
        jobDTO.setEmployeeType(job.getEmployeeType());
        jobDTO.setIndustryType(job.getIndustryType());
        jobDTO.setMinimumQualification(job.getMinimumQualification());
        jobDTO.setRecruiterId(job.getJobRecruiter().getRecruiterId());
        jobDTO.setCompanyname(job.getJobRecruiter().getCompanyname());
        jobDTO.setEmail(job.getJobRecruiter().getEmail());
        jobDTO.setMobilenumber(job.getJobRecruiter().getMobilenumber());
        jobDTO.setSpecialization(job.getSpecialization());
        jobDTO.setDescription(job.getDescription());
        jobDTO.setCreationDate(job.getCreationDate());
        jobDTO.setIsSaved(job.getIsSaved());

        Set<RecuriterSkillsDTO> skillsDTOList = job.getSkillsRequired().stream()
                .map(this::convertSkillsEntityToDTO)
                .collect(Collectors.toSet());
        jobDTO.setSkillsRequired(skillsDTOList);
        return jobDTO;
    }

    private RecuriterSkillsDTO convertSkillsEntityToDTO(RecuriterSkills skill) {
        RecuriterSkillsDTO skillDTO = new RecuriterSkillsDTO();
        skillDTO.setSkillName(skill.getSkillName());
        return skillDTO;
    }

}
