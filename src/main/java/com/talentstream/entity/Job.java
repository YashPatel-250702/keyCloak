package com.talentstream.entity;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.Lob;
import javax.persistence.ManyToMany;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;

import org.hibernate.annotations.CreationTimestamp;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.talentstream.dto.RecuriterSkillsDTO;

@Entity
@JsonIgnoreProperties({ "jobRecruiters" })

public class Job {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	@ManyToOne
	private JobRecruiter jobRecruiter;

	@Column(nullable = false)
	private String jobTitle;

	public JobRecruiter getJobRecruiter() {
		return jobRecruiter;
	}

	public void setJobRecruiter(JobRecruiter jobRecruiter) {
		this.jobRecruiter = jobRecruiter;
	}

	@Column(nullable = false)
	private int minimumExperience;

	public int getMinimumExperience() {
		return minimumExperience;
	}

	public void setMinimumExperience(int minimumExperience) {
		this.minimumExperience = minimumExperience;
	}

	@Column(nullable = false)
	private int maximumExperience;

	@Column(nullable = false)
	private double maxSalary;
	@Column(nullable = false)
	private double minSalary;
	@Column(nullable = false)
	private String promote = "no";

	private String isSaved;
	

    private String jobURL = "https://www.bitlabs.in/jobs";
    @Column(nullable = false)
    private Integer visitorCount = 0; // Default value
 
	

	public Integer getVisitorCount() {
		return visitorCount;
	}

	public void setVisitorCount(Integer visitorCount) {
		this.visitorCount = visitorCount;
	}

	public String getJobURL() {
		return jobURL;
	}

	public void setJobURL(String jobURL) {
		this.jobURL = jobURL;
	}

	public String getIsSaved() {
		return isSaved;
	}

	@JsonProperty("isSaved")
	public void setIsSaved(String isSaved) {
		this.isSaved = isSaved;
	}

	public String getPromote() {
		return promote;
	}

	public void setPromote(String promote) {
		this.promote = promote;
	}

	public double getMinSalary() {
		return minSalary;
	}

	public void setMinSalary(double minSalary) {
		this.minSalary = minSalary;
	}

	@Column(nullable = false)
	private String location;

	@Column(nullable = false)
	private String employeeType;

	@Column(nullable = false)
	private String industryType;

	@Column(nullable = false)
	private String minimumQualification;

	@Column(nullable = false)
	private String specialization;

	@ManyToMany(cascade = {
			CascadeType.PERSIST,
			CascadeType.MERGE
	})

	@JoinTable(name = "job_skills", joinColumns = @JoinColumn(name = "job_id"), inverseJoinColumns = @JoinColumn(name = "skill_id"))
	private Set<RecuriterSkills> skillsRequired = new HashSet<>();

	public void addSkillWithMinimumExperience(String skillName) {
		RecuriterSkills skill = new RecuriterSkills();
		skill.setSkillName(skillName);
		skillsRequired.add(skill);

	}

	@Column(nullable = false, length = 2000)
	private String description;

	@Lob
	@Column
	private byte[] uploadDocument;

	@CreationTimestamp
	@Column(name = "creation_date", nullable = false, updatable = false, columnDefinition = "DATE")
	private LocalDate creationDate;

	@Column(name = "job_status")
	private String jobStatus = "Apply Now";

	@Column(nullable = false)
	private String status = "active";

	@Column(columnDefinition = "int default 0")
	private int alertCount;

	@Column(name = "recent_application_date_time")
	@CreationTimestamp
	private LocalDateTime recentApplicationDateTime;

	@Column(name = "new_status", columnDefinition = "VARCHAR(255) DEFAULT 'oldApplicants'")
	private String newStatus;
	
	@OneToMany(mappedBy = "job", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonManagedReference
    private Set<ScreeningQuestion> screeningQuestions = new HashSet<>();

	public String getNewStatus() {
		return newStatus;
	}

	public void setNewStatus(String newStatus) {
		this.newStatus = newStatus;
	}

	public LocalDateTime getRecentApplicationDateTime() {
		return recentApplicationDateTime;
	}

	public void setRecentApplicationDateTime(LocalDateTime recentApplicationDateTime) {
		this.recentApplicationDateTime = recentApplicationDateTime;
	}

	public int getAlertCount() {
		return alertCount;
	}

	public void setAlertCount(int alertCount) {
		this.alertCount = alertCount;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getJobTitle() {
		return jobTitle;
	}

	public void setJobTitle(String jobTitle) {
		this.jobTitle = jobTitle;
	}

	public int getMaximumExperience() {
		return maximumExperience;
	}

	public void setMaximumExperience(int maximumExperience) {
		this.maximumExperience = maximumExperience;
	}

	public double getMaxSalary() {
		return maxSalary;
	}

	public void setMaxSalary(double maxSalary) {
		this.maxSalary = maxSalary;
	}

	public String getLocation() {
		return location;
	}

	public void setLocation(String location) {
		this.location = location;
	}

	public String getEmployeeType() {
		return employeeType;
	}

	public void setEmployeeType(String employeeType) {
		this.employeeType = employeeType;
	}

	public String getIndustryType() {
		return industryType;
	}

	public void setIndustryType(String industryType) {
		this.industryType = industryType;
	}

	public String getMinimumQualification() {
		return minimumQualification;
	}

	public void setMinimumQualification(String minimumQualification) {
		this.minimumQualification = minimumQualification;
	}

	public String getSpecialization() {
		return specialization;
	}

	public void setSpecialization(String specialization) {
		this.specialization = specialization;
	}

	public Set<RecuriterSkills> getSkillsRequired() {
		return skillsRequired;
	}

	public void setSkillsRequired(Set<RecuriterSkills> skillsRequired) {
		this.skillsRequired = skillsRequired;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public byte[] getUploadDocument() {
		return uploadDocument;
	}

	public void setUploadDocument(byte[] uploadDocument) {
		this.uploadDocument = uploadDocument;
	}

	public LocalDate getCreationDate() {
		return creationDate;
	}

	public void setCreationDate(LocalDate creationDate) {
		this.creationDate = creationDate;
	}

	public String getJobStatus() {
		return jobStatus;
	}

	public void setJobStatus(String jobStatus) {
		this.jobStatus = jobStatus;
	}
	 public void addScreeningQuestion(ScreeningQuestion question) {
	        screeningQuestions.add(question);
	        question.setJob(this);
	    }

	    public void removeScreeningQuestion(ScreeningQuestion question) {
	        screeningQuestions.remove(question);
	        question.setJob(null);
	    }
	    
	    public Set<ScreeningQuestion> getScreeningQuestions() {
	        return screeningQuestions;
	    }
	    public void setScreeningQuestions(Set<ScreeningQuestion> screeningQuestions) {
	        this.screeningQuestions.clear();
	        if (screeningQuestions != null) {
	            this.screeningQuestions.addAll(screeningQuestions);
	        }
	    }
}
