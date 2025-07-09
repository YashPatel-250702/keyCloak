package com.talentstream.entity;

public class AppliedApplicantInfo {
	private Long applyjobid;
	private Long id;
	private String name;
	private String email;
	private String mobilenumber;
	private String jobTitle;
	private	Long jobId;
	private String applicantStatus;
	private int minimumExperience;
	private String skillName;
	private String minimumQualification;
	private String location;
	private String newStatus;

	public AppliedApplicantInfo(Long applyjobid, String name, Long id, String email, String mobile, String newStatus,
			String jobTitle,Long jobId, String applicantStatus, int minimumExperience,
			String minimumQualification, String location) {
		this.applyjobid = applyjobid;
		this.name = name;
		this.id = id;
		this.email = email;
		this.mobilenumber = mobile;
		this.newStatus = newStatus;
		this.jobTitle = jobTitle;
		this.jobId=jobId;
		this.applicantStatus = applicantStatus;
		this.minimumExperience = minimumExperience;
		this.minimumQualification = minimumQualification;
		this.location = location;

	}
	
	public Long getJobId() {
		return jobId;
	}
 
	public void setJobId(Long jobId) {
		this.jobId = jobId;
	}

	public String getNewStatus() {
		return newStatus;
	}

	public void setNewStatus(String newStatus) {
		this.newStatus = newStatus;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public Long getApplyjobid() {
		return applyjobid;
	}

	public void setApplyjobid(Long applyjobid) {
		this.applyjobid = applyjobid;
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

	public String getSkillName() {
		return skillName;
	}

	public void setSkillName(String skillName) {
		this.skillName = skillName;
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

}
