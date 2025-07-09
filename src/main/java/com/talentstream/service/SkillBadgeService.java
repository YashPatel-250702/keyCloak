package com.talentstream.service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.persistence.EntityNotFoundException;
import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.talentstream.dto.ApplicantSkillBadgeDTO;
import com.talentstream.entity.Applicant;
import com.talentstream.entity.ApplicantProfile;
import com.talentstream.entity.ApplicantSkillBadge;
import com.talentstream.entity.ApplicantSkills;
import com.talentstream.entity.SkillBadge;
import com.talentstream.repository.ApplicantProfileRepository;
import com.talentstream.repository.ApplicantRepository;
import com.talentstream.repository.ApplicantSkillBadgeRepository;
import com.talentstream.repository.SkillBadgeRepository;

@Service
public class SkillBadgeService {

    @Autowired
    private SkillBadgeRepository skillBadgeRepository;
    

    @Autowired
    private ApplicantRepository applicantRepository;

    @Autowired
    private ApplicantSkillBadgeRepository applicantSkillBadgeRepository;
    @Autowired
    private ApplicantProfileRepository applicantProfileRepository;

    @Transactional
    public ResponseEntity<String> saveApplicantSkillBadge(Long applicantId, String skillBadgeName, String status) {
        try {
            // Retrieve the Applicant and SkillBadge entities
            Applicant applicant = applicantRepository.findById(applicantId)
                .orElseThrow(() -> new RuntimeException("Applicant not found with ID: " + applicantId));
            SkillBadge skillBadge = skillBadgeRepository.findByName(skillBadgeName);
            
            ApplicantSkillBadge applicantSkillBadge1=applicantSkillBadgeRepository.findByApplicantIdAndSkillBadgeId(applicantId, skillBadge.getId());

            
            // If the skillBadge is not found, throw a custom exception or return an error
            if (skillBadge == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("SkillBadge with name '" + skillBadgeName + "' not found.");
            }
            if (applicantSkillBadge1 != null && applicantSkillBadge1.getStatus().equalsIgnoreCase("FAILED")) {
            	applicantSkillBadge1.setStatus(status);
            	applicantSkillBadge1.setTestTaken(LocalDateTime.now());
            	applicantSkillBadgeRepository.save(applicantSkillBadge1);
            }else {
            // Create and save the ApplicantSkillBadge
            ApplicantSkillBadge applicantSkillBadge = new ApplicantSkillBadge();
            applicantSkillBadge.setApplicant(applicant);
            applicantSkillBadge.setSkillBadge(skillBadge);
            applicantSkillBadge.setStatus(status);
            applicantSkillBadge.setTestTaken(LocalDateTime.now());

            // Save to the repository
            
            applicantSkillBadgeRepository.save(applicantSkillBadge);
            }
            // Return success message
            return ResponseEntity.ok("ApplicantSkillBadge saved successfully");

        } catch (EntityNotFoundException e) {
            // Handle entity not found (applicant or skill badge)
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body("Error: " + e.getMessage());
        } catch (DataIntegrityViolationException e) {
            // Handle any database constraint violation errors
            return ResponseEntity.status(HttpStatus.CONFLICT)
                .body("Database error: " + e.getMessage());
        } catch (Exception e) {
            // Catch any other unexpected exceptions
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("An unexpected error occurred: " + e.getMessage());
        }
    }


    public ResponseEntity<ApplicantSkillBadgeDTO> getApplicantSkillBadges(Long id) {
        
        // Find applicant skills based on applicant ID
        List<ApplicantSkillBadge> applicantSkills = applicantSkillBadgeRepository.findByApplicantIdAndFlagAdded(id);

        // Find applicant profile, and handle any potential exception
        ApplicantProfile applicantProfile = null;
        try {
            applicantProfile = applicantProfileRepository.findByApplicantId(id);
        } catch (Exception e) {
            throw new RuntimeException("Error fetching applicant profile");
        }

        // Check if the applicant profile is null and handle it if necessary
        if (applicantProfile == null) {
            throw new EntityNotFoundException("Applicant profile not found for applicant id: " + id);
        }

     // Get all required skills from the applicant profile
        Set<ApplicantSkills> allSkills = new HashSet<>(applicantProfile.getSkillsRequired());

        // Remove skills from allSkills that match with applicant skill badges
        for (ApplicantSkillBadge applicantSkill : applicantSkills) {
            // Find any skill in allSkills that matches the applicantSkill's skill name and remove it
            allSkills.removeIf(skill -> skill.getSkillName().equalsIgnoreCase(applicantSkill.getSkillBadge().getName()));
        }

        // Create and populate DTO
        ApplicantSkillBadgeDTO applicantSkillBadgeDTO = new ApplicantSkillBadgeDTO();
     // 1. PASSED badges — group by skill name, pick the latest one if multiple
        Map<String, ApplicantSkillBadge> passedMap = applicantSkills.stream()
            .filter(b -> "PASSED".equalsIgnoreCase(b.getStatus()))
            .collect(Collectors.toMap(
                b -> b.getSkillBadge().getName().toLowerCase(),
                b -> b,
                (b1, b2) -> b1.getTestTaken().isAfter(b2.getTestTaken()) ? b1 : b2
            ));
        List<ApplicantSkillBadge> passedList = new ArrayList<>(passedMap.values());

     // 2. FAILED badges — exclude skills already in passedMap, sort by time DESC
        List<ApplicantSkillBadge> failedList = applicantSkills.stream()
            .filter(b -> "FAILED".equalsIgnoreCase(b.getStatus()))
            .filter(b -> !passedMap.containsKey(b.getSkillBadge().getName().toLowerCase()))
            .sorted(Comparator.comparing(ApplicantSkillBadge::getTestTaken)) // ASCENDING
            .collect(Collectors.toList());


        // Combine both lists
        List<ApplicantSkillBadge> finalSkillBadges = new ArrayList<>();
        finalSkillBadges.addAll(passedList);
        finalSkillBadges.addAll(failedList);

        // Set sorted list to DTO
        applicantSkillBadgeDTO.setApplicantSkillBadges(finalSkillBadges);

        applicantSkillBadgeDTO.setSkillsRequired(allSkills); // Set the required skills

        // Return the response entity with the populated DTO
        return ResponseEntity.ok(applicantSkillBadgeDTO);
    }

    
    
}

