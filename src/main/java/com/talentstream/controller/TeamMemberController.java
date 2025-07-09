package com.talentstream.controller;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.talentstream.exception.CustomException;
import com.talentstream.dto.TeamMemberDTO;
import com.talentstream.service.TeamMemberService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
@RestController
@CrossOrigin("*")
@RequestMapping("/team")
public class TeamMemberController {
 
    @Autowired
    private TeamMemberService teamMemberService;
    private static final Logger logger = LoggerFactory.getLogger(ApplicantProfileController.class);
    @PostMapping("/add/{recruiterId}/team-members")
    public ResponseEntity<Object> addTeamMemberToRecruiter(
            @PathVariable Long recruiterId,
            @RequestBody TeamMemberDTO teamMember
    ) {
        try {
            TeamMemberDTO savedTeamMember = teamMemberService.addTeamMemberToRecruiter(recruiterId, teamMember);
            return ResponseEntity.status(HttpStatus.CREATED).body(savedTeamMember);
        } catch (CustomException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Recruiter with ID " + recruiterId + " not found.");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to add team member. Please try again.");
        }
    }
 
  
    
    @GetMapping("get/teammembers/{recruiterId}")
    public ResponseEntity<Object> getTeammembersByRecruiter(@PathVariable("recruiterId") long recruiterId) {
        try {
            List<TeamMemberDTO> teamMembers = teamMemberService.getTeammembersByRecruiter(recruiterId);
            if (teamMembers.isEmpty()) {
                return ResponseEntity.notFound().build();
            } else {
                return ResponseEntity.ok(teamMembers);
            }
        } catch (CustomException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Recruiter with ID " + recruiterId + " not found.");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to retrieve team members. Please try again.");
        }
    }
    
    @DeleteMapping("delete/{teamMemberId}")
    public ResponseEntity<Object> deleteTeamMember(@PathVariable Long teamMemberId) {
        try {
            teamMemberService.deleteTeamMemberById(teamMemberId);
            return ResponseEntity.ok("Team Member with ID " + teamMemberId + " deleted successfully");
        } catch (CustomException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Team Member with ID " + teamMemberId + " not found.");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to delete Team Member. Please try again.");
        }
    }
    
    @PutMapping("/{teamMemberId}/reset-password")
    public ResponseEntity<Object> resetPassword(
            @PathVariable Long teamMemberId,
            @RequestParam("newPassword") String newPassword
    ) {
        try {
            teamMemberService.resetTeamMemberPassword(teamMemberId, newPassword);
            return ResponseEntity.ok("Password for Team Member with ID " + teamMemberId + " reset successfully");
        } catch (CustomException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Team Member with ID " + teamMemberId + " not found.");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to reset password for Team Member. Please try again.");
        }
    }
 
}
    
    