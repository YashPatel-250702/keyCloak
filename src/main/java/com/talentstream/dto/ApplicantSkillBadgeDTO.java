package com.talentstream.dto;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

import javax.persistence.ManyToOne;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.talentstream.entity.Applicant;
import com.talentstream.entity.ApplicantSkillBadge;
import com.talentstream.entity.ApplicantSkills;
import com.talentstream.entity.SkillBadge;

public class ApplicantSkillBadgeDTO {

	    
	    
	    private Set<ApplicantSkills> skillsRequired;
	    
	    private List<ApplicantSkillBadge> applicantSkillBadges;
	    
	   

		public Set<ApplicantSkills> getSkillsRequired() {
			return skillsRequired;
		}

		public void setSkillsRequired(Set<ApplicantSkills> skillsRequired) {
			this.skillsRequired = skillsRequired;
		}

		public List<ApplicantSkillBadge> getApplicantSkillBadges() {
			return applicantSkillBadges;
		}

		public void setApplicantSkillBadges(List<ApplicantSkillBadge> applicantSkillBadges) {
			this.applicantSkillBadges = applicantSkillBadges;
		}
	    
	    

	    
}
