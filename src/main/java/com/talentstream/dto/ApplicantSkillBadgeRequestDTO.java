package com.talentstream.dto;

public class ApplicantSkillBadgeRequestDTO {
	
	private Long applicantId;
    private String skillBadgeName; // Use String if you’re passing the name instead of ID
    private String status;
	public Long getApplicantId() {
		return applicantId;
	}
	public void setApplicantId(Long applicantId) {
		this.applicantId = applicantId;
	}
	public String getSkillBadgeName() {
		return skillBadgeName;
	}
	public void setSkillBadgeName(String skillBadgeName) {
		this.skillBadgeName = skillBadgeName;
	}
	public String getStatus() {
		return status;
	}
	public void setStatus(String status) {
		this.status = status;
	}
    
    
    

}
