package com.talentstream.entity;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.talentstream.dto.RecuriterSkillsDTO;

import java.util.HashSet;



public class AppliedApplicantInfoDTO {
	private Long applyjobid;
	private Long id;
	private String name;
	private String email;
	private String mobilenumber;
	private String jobTitle;
	private Long jobId;
	private String applicantStatus;
	private int minimumExperience;
	private List<String> skillName;
	private String minimumQualification;
	private String location;
	private String newStatus;
	private String experience;
    private Set<String> preferredJobLocations = new HashSet<>();
    private String qualification;
    private String specialization;
    private Double apptitudeScore;
    private Double technicalScore;
    private String preScreenedCondition;
    private int matchPercentage;
    private Set<ApplicantSkills> matchedSkills;
    private Set<RecuriterSkillsDTO> nonMatchedSkills;
    private Set<ApplicantSkills> additionalSkills;
    private List<ApplicantSkillBadge> applicantSkillBadges;
    
    
    
	
	public List<ApplicantSkillBadge> getApplicantSkillBadges() {
		return applicantSkillBadges;
	}

	public void setApplicantSkillBadges(List<ApplicantSkillBadge> applicantSkillBadges) {
		this.applicantSkillBadges = applicantSkillBadges;
	}

	public int getMatchPercentage() {
		return matchPercentage;
	}

	public void setMatchPercentage(int matchPercentage) {
		this.matchPercentage = matchPercentage;
	}

	public Set<ApplicantSkills> getMatchedSkills() {
		return matchedSkills;
	}

	public void setMatchedSkills(Set<ApplicantSkills> matchedSkills) {
		this.matchedSkills = matchedSkills;
	}

	public Set<RecuriterSkillsDTO> getNonMatchedSkills() {
		return nonMatchedSkills;
	}

	public void setNonMatchedSkills(Set<RecuriterSkillsDTO> nonMatchedSkills) {
		this.nonMatchedSkills = nonMatchedSkills;
	}

	public Set<ApplicantSkills> getAdditionalSkills() {
		return additionalSkills;
	}

	public void setAdditionalSkills(Set<ApplicantSkills> additionalSkills) {
		this.additionalSkills = additionalSkills;
	}

	public Double getApptitudeScore() {
		return apptitudeScore;
	}

	public void setApptitudeScore(Double apptitudeScore) {
		this.apptitudeScore = apptitudeScore;
	}

	public Double getTechnicalScore() {
		return technicalScore;
	}

	public void setTechnicalScore(Double technicalScore) {
		this.technicalScore = technicalScore;
	}

	public String getPreScreenedCondition() {
		return preScreenedCondition;
	}

	public void setPreScreenedCondition(String preScreenedCondition) {
		this.preScreenedCondition = preScreenedCondition;
	}

	public Set<String> getPreferredJobLocations() {
		return preferredJobLocations;
	}

	public void setPreferredJobLocations(Set<String> preferredJobLocations) {
		this.preferredJobLocations = preferredJobLocations;
	}

	public String getQualification() {
		return qualification;
	}

	public void setQualification(String qualification) {
		this.qualification = qualification;
	}

	public String getSpecialization() {
		return specialization;
	}

	public void setSpecialization(String specialization) {
		this.specialization = specialization;
	}

	
	

	public Long getJobId() {
		return jobId;
	}
 
	public void setJobId(Long jobId) {
		this.jobId = jobId;
	}
	
	public Map<String, Integer> getSkills() {
		return skills;
	}

	public void setSkills(Map<String, Integer> skills) {
		this.skills = skills;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public AppliedApplicantInfoDTO() {
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getMobilenumber() {
		return mobilenumber;
	}

	public void setMobilenumber(String mobilenumber) {
		this.mobilenumber = mobilenumber;
	}

	public String getJobTitle() {
		return jobTitle;
	}

	public void setJobTitle(String jobTitle) {
		this.jobTitle = jobTitle;
	}

	public String getApplicantStatus() {
		return applicantStatus;
	}

	public void setApplicantStatus(String applicantStatus) {
		this.applicantStatus = applicantStatus;
	}

	public int getMinimumExperience() {
		return minimumExperience;
	}

	public void setMinimumExperience(int minimumExperience) {
		this.minimumExperience = minimumExperience;
	}

	public List<String> getSkillName() {
		return skillName;
	}

	public void setSkillName(List<String> skills2) {
		this.skillName = skills2;
	}

	public String getMinimumQualification() {
		return minimumQualification;
	}

	public void setMinimumQualification(String minimumQualification) {
		this.minimumQualification = minimumQualification;
	}

	public String getLocation() {
		return location;
	}

	public void setLocation(String location) {
		this.location = location;
	}

	public Long getApplyjobid() {
		return applyjobid;
	}

	public void setApplyjobid(Long applyjobid) {
		this.applyjobid = applyjobid;
	}

	private Map<String, Integer> skills = new HashMap<>();

	public void addSkill(String skillName, int minimumExperience) {
		skills.put(skillName, minimumExperience);
	}

	public String getNewStatus() {
		return newStatus;
	}

	public void setNewStatus(String newStatus) {
		this.newStatus = newStatus;
	}

	public String getExperience() {
		return experience;
	}

	public void setExperience(String experience) {
		this.experience = experience;
	}
}
