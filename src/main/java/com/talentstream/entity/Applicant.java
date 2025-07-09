package com.talentstream.entity;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonManagedReference;

/**
 * @author Madar
 *
 */
@Entity
public class Applicant {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;
	private String name;

	@NotBlank(message = "Email is required.")
	@Pattern(regexp = "^$|^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$", message = "Invalid email format and white spaces are not allowed.")
	private String email;
	@Column(name = "mobile")
	private String mobilenumber;
	private String password;
	@OneToMany(mappedBy = "applicant")
	@JsonIgnore
	private Set<ApplyJob> appliedJobs = new HashSet<>();
	@OneToMany(mappedBy = "applicant")
	@JsonIgnore
	private Set<SavedJob> savedJobs = new HashSet<>();

	@OneToMany(mappedBy = "applicant", cascade = CascadeType.ALL)
	@JsonIgnore
	private Set<Alerts> alerts = new HashSet<>();

	public Set<Alerts> getAlerts() {
		return alerts;
	}

	@Column(nullable = false)
	private String roles = "ROLE_JOBAPPLICANT";

	@Column(columnDefinition = "int default 0")
	private int alertCount;

	@Column(name = "resume_id", columnDefinition = "VARCHAR(255) DEFAULT 'Not available'")
	private String resumeId = "Not available";

	private boolean localResume = false;
	@Column(name = "utm_source", columnDefinition = "VARCHAR(255) DEFAULT 'Self'")
	private String utmSource;

	
	@OneToMany(mappedBy = "applicant", cascade = CascadeType.ALL)
    @JsonManagedReference
    private List<ApplicantSkillBadge> applicantSkillBadges;
	
	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS")
	private LocalDateTime createdAt;
	
	
	public LocalDateTime getCreatedAt() {
		return createdAt;
	}
 
	public void setCreatedAt(LocalDateTime createdAt) {
		this.createdAt = createdAt;
	} 
	
	public List<ApplicantSkillBadge> getApplicantSkillBadges() {
		return applicantSkillBadges;
	}

	public void setApplicantSkillBadges(List<ApplicantSkillBadge> applicantSkillBadges) {
		this.applicantSkillBadges = applicantSkillBadges;
	}

	public String getUtmSource() {
		return utmSource;
	}

	public void setUtmSource(String utmSource) {
		this.utmSource = utmSource;
	}

	public boolean isLocalResume() {
		return localResume;
	}

	public void setLocalResume(boolean localResume) {
		this.localResume = localResume;
	}

	public String getResumeId() {
		return resumeId;
	}

	public void setResumeId(String resumeId) {
		this.resumeId = resumeId;
	}

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
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

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public Set<ApplyJob> getAppliedJobs() {
		return appliedJobs;
	}

	public void setAppliedJobs(Set<ApplyJob> appliedJobs) {
		this.appliedJobs = appliedJobs;
	}

	public Set<SavedJob> getSavedJobs() {
		return savedJobs;
	}

	public void setSavedJobs(Set<SavedJob> savedJobs) {
		this.savedJobs = savedJobs;
	}

	public String getRoles() {
		return roles;
	}

	public void setRoles(String roles) {
		this.roles = roles;
	}

	public int getAlertCount() {
		return alertCount;
	}

	public void setAlertCount(int alertCount) {
		this.alertCount = alertCount;
	}

	public void setAlerts(Set<Alerts> alerts) {
		this.alerts = alerts;
	}
}
