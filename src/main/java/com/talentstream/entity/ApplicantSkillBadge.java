package com.talentstream.entity;

import java.time.LocalDateTime;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;

import com.fasterxml.jackson.annotation.JsonBackReference;

@Entity
public class ApplicantSkillBadge {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JsonBackReference
    private Applicant applicant;

    @ManyToOne
    private SkillBadge skillBadge;

    private String status;

    private LocalDateTime testTaken;
    
    
    private String flag = "added";  // Default value
    
    @PrePersist
    @PreUpdate
    protected void onPersistOrUpdate() {
        this.testTaken = LocalDateTime.now();
    }

    public String getFlag() {
		return flag;
	}

	public void setFlag(String flag) {
		this.flag = flag;
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

	public SkillBadge getSkillBadge() {
		return skillBadge;
	}

	public void setSkillBadge(SkillBadge skillBadge) {
		this.skillBadge = skillBadge;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public LocalDateTime getTestTaken() {
		return testTaken;
	}

	public void setTestTaken(LocalDateTime testTaken) {
		this.testTaken = testTaken;
	}

   
    
    
}
