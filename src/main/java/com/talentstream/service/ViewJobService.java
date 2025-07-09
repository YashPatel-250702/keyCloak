package com.talentstream.service;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import com.talentstream.dto.JobDTO;
import com.talentstream.entity.ApplicantProfile;
import com.talentstream.entity.ApplicantSkills;
import com.talentstream.entity.ApplyJob;
import com.talentstream.entity.Job;
import com.talentstream.entity.RecuriterSkills;
import com.talentstream.exception.CustomException;
import com.talentstream.repository.ApplicantProfileRepository;
import com.talentstream.repository.JobRepository;

@Service
public class ViewJobService {
    @Autowired
    private JobRepository jobRepository;
    @Autowired
    private ApplyJobService applyJobService;
    @Autowired
    private final ApplicantProfileRepository applicantProfileRepository = null;
    private static final Logger logger = LoggerFactory.getLogger(ViewJobService.class);
    private static final String NOT_FOUND_MESG = " not found.";

    private Job getJobById(Long jobId) {
        return jobRepository.findById(jobId)
                .orElseThrow(() -> new CustomException("Job ID " + jobId + " not found", HttpStatus.NOT_FOUND));
    }

    public ResponseEntity<JobDTO> getJobDetailsForApplicant(Long jobId) {
        Job job = getJobById(jobId);
        JobDTO jobDTO = new JobDTO();
        jobDTO.setRecruiterId(job.getJobRecruiter().getRecruiterId());
        jobDTO.setCompanyname(job.getJobRecruiter().getCompanyname());
        jobDTO.setEmail(job.getJobRecruiter().getEmail());
        jobDTO.setJobStatus(job.getJobStatus());
        jobDTO.setJobTitle(job.getJobTitle());
        jobDTO.setMinimumExperience(job.getMinimumExperience());
        jobDTO.setMaximumExperience(job.getMaximumExperience());
        jobDTO.setMinSalary(job.getMinSalary());
        jobDTO.setMaxSalary(job.getMaxSalary());
        jobDTO.setLocation(job.getLocation());
        jobDTO.setEmployeeType(job.getEmployeeType());
        jobDTO.setIndustryType(job.getIndustryType());
        jobDTO.setSpecialization(job.getSpecialization());
        jobDTO.setDescription(job.getDescription());
        jobDTO.setCreationDate(job.getCreationDate());
        jobDTO.setJobURL(job.getJobURL());
        logger.info("Job Recruiter ID: {}", job.getJobRecruiter().getRecruiterId());
        return ResponseEntity.ok(jobDTO);
    }

    public ResponseEntity<?> getJobDetailsForApplicant(Long jobId, Long applicantId) {
        final ModelMapper modelMapper = new ModelMapper();
        // Retrieve job details
        Job job = getJobById(jobId);

        // Retrieve applicant profile
        ApplicantProfile applicantProfile = applicantProfileRepository.findByApplicantId(applicantId);
        if (applicantProfile == null) {
            throw new CustomException("Applicant with ID " + applicantId + NOT_FOUND_MESG,
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
        // Define the mapping between skills and suggested courses
        Map<String, String> skillToCourseMap = new HashMap<>();
        skillToCourseMap.put("HTML", "HTML&CSS");
        skillToCourseMap.put("CSS", "HTML&CSS");
        skillToCourseMap.put("JAVA", "JAVA");
        skillToCourseMap.put("PYTHON", "PYTHON");
        skillToCourseMap.put("MYSQL", "MYSQL");
        skillToCourseMap.put("SQL", "MYSQL");
        skillToCourseMap.put("SQL-SERVER", "MYSQL");
        skillToCourseMap.put("JAVASCRIPT", "JAVASCRIPT");
        skillToCourseMap.put("REACT", "REACT");
        skillToCourseMap.put("SPRING", "SPRING BOOT");
        skillToCourseMap.put("SPRING BOOT", "SPRING BOOT");

        List<String> suggestedCourses = List.of("HTML&CSS", "JAVA", "PYTHON", "MYSQL", "SQL", "JAVASCRIPT", "REACT",
                "SPRING", "SPRING BOOT", "SQL-SERVER");

        // Get applicant and job skills
        Set<ApplicantSkills> applicantSkills = applicantProfile.getSkillsRequired();
        Set<RecuriterSkills> jobSkills = job.getSkillsRequired();

        // Initialize sets for matching skills
        Set<ApplicantSkills> matchedSkills = new HashSet<>();
        Set<ApplicantSkills> neitherMatchedNorNonMatchedSkills = new HashSet<>(applicantSkills);

        // Identify matched skills
        for (ApplicantSkills applicantSkill : applicantSkills) {
            if (jobSkills.stream()
                    .anyMatch(jobSkill -> jobSkill.getSkillName().equalsIgnoreCase(applicantSkill.getSkillName()))) {
                matchedSkills.add(applicantSkill);
                neitherMatchedNorNonMatchedSkills.remove(applicantSkill);
            }
        }

        double matchPercentage = ((double) matchedSkills.size() / jobSkills.size()) * 100;
        int roundedMatchPercentage = (int) Math.round(matchPercentage);
        String matchStatus = (matchPercentage <= 45) ? "Poor Match"
                : (matchPercentage <= 79) ? "Fair Match" : "Good Match";

        // Identify non-matched skills
        Set<RecuriterSkills> nonMatchedSkills = new HashSet<>(jobSkills);
        nonMatchedSkills.removeIf(jobSkill -> matchedSkills.stream()
                .anyMatch(matchedSkill -> matchedSkill.getSkillName().equalsIgnoreCase(jobSkill.getSkillName())));

        // Determine suggested courses based on non-matched skills
        List<String> nonMatchedSkillNames = nonMatchedSkills.stream().map(RecuriterSkills::getSkillName)
                .map(String::toUpperCase).collect(Collectors.toList());
        // Step 2: Map to courses and filter
        List<String> matchedCourses = nonMatchedSkillNames.stream().map(skill -> skillToCourseMap.get(skill))
                .filter(course -> course != null && suggestedCourses.contains(course)).distinct()
                .collect(Collectors.toList());// Collect into a list
        // Remove matched skills from job skills
        jobSkills.removeIf(jobSkill -> matchedSkills.stream()
                .anyMatch(matchedSkill -> matchedSkill.getSkillName().equalsIgnoreCase(jobSkill.getSkillName())));
        job.setSkillsRequired(jobSkills);
        // Map job details to DTO
        JobDTO jobDTO = modelMapper.map(job, JobDTO.class);
        jobDTO.setRecruiterId(job.getJobRecruiter().getRecruiterId());
        jobDTO.setCompanyname(job.getJobRecruiter().getCompanyname());
        jobDTO.setEmail(job.getJobRecruiter().getEmail());
        jobDTO.setMatchedSkills(matchedSkills);
        jobDTO.setMatchPercentage(roundedMatchPercentage);
        jobDTO.setMatchStatus(matchStatus);
        jobDTO.setSugesstedCourses(matchedCourses);
        jobDTO.setAdditionalSkills(neitherMatchedNorNonMatchedSkills);
        // Check if the applicant has already applied
        ApplyJob applyJob = applyJobService.getByJobAndApplicant(jobId, applicantId);
        jobDTO.setJobStatus((applyJob != null) ? "Already Applied" : "Apply now");
       if (applyJob != null) {
            jobDTO.setApplyJobId(applyJob.getApplyjobid());
        }
        return ResponseEntity.ok(jobDTO);
    }

    public ResponseEntity<?> getJobDetailsForApplicantSkillMatch(Long jobId, Long applicantId) {
        final ModelMapper modelMapper = new ModelMapper();
        Job job = jobRepository.findById(jobId).orElse(null);
        if (job == null) {
            throw new CustomException("Job with ID " + jobId + " not found.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
        ApplicantProfile applicantProfile = applicantProfileRepository.findByApplicantId(applicantId);
        if (applicantProfile == null) {
            throw new CustomException("Applicant with ID " + applicantId + " not found.",
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
        Set<ApplicantSkills> applicantSkills = applicantProfile.getSkillsRequired();
        Set<RecuriterSkills> jobSkills = job.getSkillsRequired(); // Assuming Job has a method to get required skills
        Set<ApplicantSkills> matchedSkills = new HashSet<>();
        Set<ApplicantSkills> neitherMatchedNorNonMatchedSkills = new HashSet<>(applicantSkills);
        int originalJobSkillsSize = jobSkills.size();
        for (ApplicantSkills applicantSkill : applicantSkills) {
            boolean isMatched = jobSkills.stream()
                    .anyMatch(jobSkill -> jobSkill.getSkillName().equalsIgnoreCase(applicantSkill.getSkillName()));
            if (isMatched) {
                matchedSkills.add(applicantSkill);
                neitherMatchedNorNonMatchedSkills.remove(applicantSkill);
            }
        }
        // Remove matched skills from jobSkills
        jobSkills.removeIf(jobSkill -> matchedSkills.stream()
                .anyMatch(matchedSkill -> matchedSkill.getSkillName().equalsIgnoreCase(jobSkill.getSkillName())));
        job.setSkillsRequired(jobSkills);
        double matchPercentage = ((double) matchedSkills.size() / originalJobSkillsSize) * 100;
        System.out.println(matchPercentage + " match ");
        int roundedMatchPercentage = (int) Math.round(matchPercentage);
        System.out.println(roundedMatchPercentage + " round ");
        JobDTO jobDTO = modelMapper.map(job, JobDTO.class);
        jobDTO.setMatchPercentage(roundedMatchPercentage);
        jobDTO.setMatchedSkills(matchedSkills);
        jobDTO.setAdditionalSkills(neitherMatchedNorNonMatchedSkills);
        return ResponseEntity.ok(jobDTO);
    }
}
