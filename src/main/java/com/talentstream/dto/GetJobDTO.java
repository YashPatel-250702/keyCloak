package com.talentstream.dto;

import java.time.LocalDate;

import com.fasterxml.jackson.annotation.JsonFormat;

public class GetJobDTO {
	private Long id;
	private int minimumExperience;
	private int maximumExperience;
	private String jobTitle;
	private double minSalary;
	private double maxSalary;
	private String employeeType;
	private String industryType;
	private String location;
	@JsonFormat(pattern = "yyyy-MM-dd")
	private LocalDate creationDate;
	private String companyname;

	public GetJobDTO(Long id, int minimumExperience, int maximumExperience, String jobTitle, double minSalary,
			double maxSalary, String employeeType, String industryType, LocalDate creationDate, String location,
			String companyname) {
		super();
		this.id = id;
		this.minimumExperience = minimumExperience;
		this.maximumExperience = maximumExperience;
		this.jobTitle = jobTitle;
		this.minSalary = minSalary;
		this.maxSalary = maxSalary;
		this.employeeType = employeeType;
		this.industryType = industryType;
		this.location = location;
		this.creationDate = creationDate;
		this.companyname = companyname;
	}

	public String getCompanyname() {
		return companyname;
	}

	public void setCompanyname(String companyname) {
		this.companyname = companyname;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
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

	public String getJobTitle() {
		return jobTitle;
	}

	public void setJobTitle(String jobTitle) {
		this.jobTitle = jobTitle;
	}

	public double getMinSalary() {
		return minSalary;
	}

	public void setMinSalary(double minSalary) {
		this.minSalary = minSalary;
	}

	public double getMaxSalary() {
		return maxSalary;
	}

	public void setMaxSalary(double maxSalary) {
		this.maxSalary = maxSalary;
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

	public LocalDate getCreationDate() {
		return creationDate;
	}

	public void setCreationDate(LocalDate creationDate) {
		this.creationDate = creationDate;
	}

	public String getLocation() {
		return location;
	}

	public void setLocation(String location) {
		this.location = location;
	}

}
