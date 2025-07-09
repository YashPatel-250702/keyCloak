package com.talentstream.controller;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.talentstream.dto.ApplicantSkillBadgeDTO;
import com.talentstream.dto.ApplicantSkillBadgeRequestDTO;
import com.talentstream.entity.ApplicantSkillBadge;
import com.talentstream.service.SkillBadgeService;

@RestController
@RequestMapping("/skill-badges")
public class SkillBadgeController {

    @Autowired
    private SkillBadgeService skillBadgeService;
    
    @PostMapping("/save")
    public ResponseEntity<String> saveSkillBadge(@RequestBody ApplicantSkillBadgeRequestDTO request) {
    	ResponseEntity<String> result = skillBadgeService.saveApplicantSkillBadge(
            request.getApplicantId(),
            request.getSkillBadgeName(), // Assuming service method needs skillBadgeName
            request.getStatus()
        );
    	return result;
    }
    
    @GetMapping("/{id}/skill-badges")
    public ResponseEntity<ApplicantSkillBadgeDTO> getApplicantSkillBadges(@PathVariable Long id) {
    	
    	
        return skillBadgeService.getApplicantSkillBadges(id);
    }
    
    
}
