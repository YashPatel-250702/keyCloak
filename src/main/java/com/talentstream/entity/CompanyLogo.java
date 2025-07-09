package com.talentstream.entity;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;


@Entity
public class CompanyLogo {
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String logoName;
    
   
    @OneToOne//(mappedBy = "companyLogo", cascade = CascadeType.ALL)
    @JoinColumn(name = "jobRecruiter_id")
    private JobRecruiter jobRecruiter;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	
	public String getLogoName() {
		return logoName;
	}

	public void setLogoName(String logoName) {
		this.logoName = logoName;
	}

	public JobRecruiter getJobRecruiter() {
		return jobRecruiter;
	}

	public void setJobRecruiter(JobRecruiter jobRecruiter) {
		this.jobRecruiter = jobRecruiter;
	}
    
}