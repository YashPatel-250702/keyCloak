package com.talentstream.entity;

import java.time.LocalDate;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;

@Entity
public class ApplicantStatusHistory {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;
	@ManyToOne
	@JoinColumn(name = "applyjobid")
	private ApplyJob applyJob;

	private String status;
	@Column(columnDefinition = "DATE")
	private LocalDate changeDate;

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public ApplyJob getApplyJob() {
		return applyJob;
	}

	public void setApplyJob(ApplyJob applyJob) {
		this.applyJob = applyJob;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public LocalDate getChangeDate() {
		return changeDate;
	}

	public void setChangeDate(LocalDate changeDate) {
		this.changeDate = changeDate;
	}

}
