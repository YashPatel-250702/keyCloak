package com.talentstream.dto;

import java.time.LocalDate;
import java.util.List;
import java.util.Set;

import javax.validation.constraints.AssertTrue;
import javax.validation.constraints.DecimalMax;
import javax.validation.constraints.DecimalMin;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import com.talentstream.entity.ApplicantSkillBadge;
import com.talentstream.entity.ApplicantSkills;
import com.talentstream.entity.ScreeningQuestion;

public class JobDTO {
	private Long id;
	private Long recruiterId;
	private byte[] logoFile;

	private String saveJobStatus = "Not Saved";

	private String isSaved;
	
	private Set<ScreeningQuestion> screeningQuestions;
	
	private Double aptitudeScore;  
	
	private Double technicalScore;
	
	private List<ApplicantSkillBadge> applicantSkillBadges;

	public List<ApplicantSkillBadge> getApplicantSkillBadges() {
		return applicantSkillBadges;
	}

	public void setApplicantSkillBadges(List<ApplicantSkillBadge> applicantSkillBadges) {
		this.applicantSkillBadges = applicantSkillBadges;
	}

	public Double getAptitudeScore() {
		return aptitudeScore;
	}

	public void setAptitudeScore(Double aptitudeScore) {
		this.aptitudeScore = aptitudeScore;
	}

	public Double getTechnicalScore() {
		return technicalScore;
	}

	public void setTechnicalScore(Double technicalScore) {
		this.technicalScore = technicalScore;
	}

	public String getIsSaved() {
		return isSaved;
	}

	public void setIsSaved(String isSaved) {
		this.isSaved = isSaved;
	}

	public String getSaveJobStatus() {
		return saveJobStatus;
	}

	public void setSaveJobStatus(String saveJobStatus) {
		this.saveJobStatus = saveJobStatus;
	}

	public byte[] getLogoFile() {
		return logoFile;
	}

	public void setLogoFile(byte[] imageBytes) {
		this.logoFile = imageBytes;
	}

	public String getCompanyname() {
		return companyname;
	}

	public void setCompanyname(String companyname) {
		this.companyname = companyname;
	}

	public String getMobilenumber() {
		return mobilenumber;
	}

	public void setMobilenumber(String mobilenumber) {
		this.mobilenumber = mobilenumber;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

		
		@NotBlank(message = "JobTitle required")
		private String jobTitle;
		
		
		@NotBlank(message = "Description required")
		@Size(min = 15,  message = "description atleast be 15 characters")
		private String description;
		
		@NotNull(message = "MinimumExperience required")
		private int minimumExperience;
	    
		@NotNull(message = "MaximumExperience required")
		@Min(value = 0, message = "Maximum experience cannot be negative")
		private int maximumExperience;
		
		@AssertTrue(message = "Minimum experience should be less than or equal to maximum experience")
		private boolean isMinimumExperienceLessThanMaximum() {
		    return minimumExperience <= maximumExperience;
		}
	    
		@NotNull(message = "MinimumSalary required")
		@DecimalMin(value = "0.0", inclusive = false, message = "Minimum salary cannot be negative")
		private double minSalary;
		
		@NotNull(message = "MaximumSalary required")
		@DecimalMax(value = "1.0E9", inclusive = false, message = "Maximum salary exceeds the allowed limit")
		private double maxSalary;
		
		@AssertTrue(message = "Minimum salary should be less thanor equal to maximum salary")
	    private boolean isMinimumSalaryLessThanMaximum() {
	        return minSalary <= maxSalary;
	    }
		
		@NotBlank(message = "MinimumQualification required")
		private String minimumQualification;
		
	//	@Size(min = 3,  message = "Specialization atleast be 3 characters")
		private String specialization;
		
		@NotBlank(message = "Location required")
		private String location;
		
//		@Size(min = 2, max = 2, message = "Industry type must have exactly 2 characters")
		private String industryType;
		
//		@Size(min = 2, message = "jobHighlights atleast be 2 characters")
//		private String jobHighlights;
		
		@NotBlank(message = "JobType required")
		private String employeeType;
		
		@NotNull(message = "Skills required")
		private Set<RecuriterSkillsDTO> skillsRequired;
		
		private Set<ApplicantSkills> matchedSkills;
		private Set<ApplicantSkills> additionalSkills;
		
		public Set<ApplicantSkills> getAdditionalSkills() {
			return additionalSkills;
		}

		public void setAdditionalSkills(Set<ApplicantSkills> additionalSkills) {
			this.additionalSkills = additionalSkills;
		}


		private int matchPercentage;
		 private String matchStatus;
		 private List<String> sugesstedCourses;
		
		 
		public List<String> getSugesstedCourses() {
			return sugesstedCourses;
		}
		public void setSugesstedCourses(List<String> sugesstedCourses) {
			this.sugesstedCourses = sugesstedCourses;
		}
		public int getMatchPercentage() {
			return matchPercentage;
		}
		public void setMatchPercentage(int matchPercentage) {
			this.matchPercentage = matchPercentage;
		}
		public String getMatchStatus() {
			return matchStatus;
		}
		public void setMatchStatus(String matchStatus) {
			this.matchStatus = matchStatus;
		}

		private String companyname;
	    private String mobilenumber;
	    private String email;
	    private LocalDate creationDate;
	    private String jobStatus="Apply Now";
	    private String jobURL;
	    private Integer visitorCount;
	    
	    
	    
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

		public Set<ApplicantSkills> getMatchedSkills() {
			return matchedSkills;
		}
		public void setMatchedSkills(Set<ApplicantSkills> matchedSkills) {
			this.matchedSkills = matchedSkills;
		}

		private Long applyJobId;
	    private String promote = "no";
	    
	    
	    public String getPromote() {
			return promote;
		}
	     public void setPromote(String promote) {
			this.promote = promote;
		}
	    public Long getApplyJobId() {
	    	        return applyJobId;
	    	    }
	    	    public void setApplyJobId(Long applyJobId) {
	    	        this.applyJobId = applyJobId;
	    	    }
		public String getJobStatus() {
			return jobStatus;
		}
		public void setJobStatus(String jobStatus) {
			this.jobStatus = jobStatus;
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
		public int getMinimumExperience() {
			return minimumExperience;
		}
		public void setMinimumExperience(int minimumExperience) {
			this.minimumExperience = minimumExperience;
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
		public double getMinSalary() {
			return minSalary;
		}
		public void setMinSalary(double minSalary) {
			this.minSalary = minSalary;
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
		public Set<RecuriterSkillsDTO> getSkillsRequired() {
			return skillsRequired;
		}
		public void setSkillsRequired(Set<RecuriterSkillsDTO> skillsDTOList) {
			this.skillsRequired = skillsDTOList;
		}
//		public String getJobHighlights() {
//			return jobHighlights;
//		}
//		public void setJobHighlights(String jobHighlights) {
//			this.jobHighlights = jobHighlights;
//		}
		public String getDescription() {
			return description;
		}
		public void setDescription(String description) {
			this.description = description;
		}
		public Long getRecruiterId() {
			return recruiterId;
		}
		public void setRecruiterId(Long recruiterId) {
			this.recruiterId = recruiterId;
		}
		public LocalDate getCreationDate() {
			return creationDate;
		}
		public void setCreationDate(LocalDate creationDate) {
			this.creationDate = creationDate;
		}
		  public Set<ScreeningQuestion> getScreeningQuestions() {
		        return screeningQuestions;
		    }

		    public void setScreeningQuestions(Set<ScreeningQuestion> screeningQuestions) {
		        this.screeningQuestions = screeningQuestions;
		    }

}
