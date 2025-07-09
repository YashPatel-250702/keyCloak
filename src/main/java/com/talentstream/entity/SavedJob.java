package com.talentstream.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
@Entity
@Table(name="ApplicantSavedjob")
public class SavedJob {
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

	@ManyToOne
    @JoinColumn(name = "applicantregistration_id")
    private Applicant applicant;

    @ManyToOne
    @JoinColumn(name = "job_id")
    private Job job;
    
    @Column(name = "save_job_status")
    private String saveJobStatus;
    
	public String getSaveJobStatus() {
		return saveJobStatus;
	}

	public void setSaveJobStatus(String saveJobStatus) {
		this.saveJobStatus = saveJobStatus;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	

	public Applicant getApplicant() {
		return applicant;
	}

	public void setApplicant(Applicant applicant) {
		this.applicant = applicant;
	}

	public Job getJob() {
		return job;
	}

	public void setJob(Job job) {
		this.job = job;
	}
    

}
