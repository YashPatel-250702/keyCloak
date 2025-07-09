
package com.talentstream.entity;

import java.time.LocalDateTime;

import java.util.List;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.Table;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.PrePersist;

@Entity
@Table(name = "Applyjob")
public class ApplyJob {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long applyjobid;
	@ManyToOne
	@JoinColumn(name = "applicantId")
	private Applicant applicant;
	@ManyToOne
	@JoinColumn(name = "job_id")
	private Job job;
	@Column(columnDefinition = "TIMESTAMP")
	private LocalDateTime applicationDate;
	@Column(nullable = false)
	private String applicantStatus = "New";
	@OneToMany(mappedBy = "applyJob", cascade = CascadeType.ALL)
	@JsonManagedReference
	private List<ScheduleInterview> scheduleInterviews;

	@Column(columnDefinition = "TIMESTAMP")
	private LocalDateTime changeDate;

	@Column(columnDefinition = "TEXT")
	private String reason;

	public String getReason() {
		return reason;
	}

	public void setReason(String reason) {
		this.reason = reason;
	}

	public LocalDateTime getChangeDate() {
		return changeDate;
	}

	public void setChangeDate(LocalDateTime changeDate) {
		this.changeDate = changeDate;
	}

	public List<ScheduleInterview> getScheduleInterviews() {
		return scheduleInterviews;
	}

	public void setScheduleInterviews(List<ScheduleInterview> scheduleInterviews) {
		this.scheduleInterviews = scheduleInterviews;
	}

	public Long getApplyjobid() {
		return applyjobid;
	}

	public void setApplyjobid(Long applyjobid) {
		this.applyjobid = applyjobid;
	}

	public LocalDateTime getApplicationDate() {
		return applicationDate;
	}

	public void setApplicationDate(LocalDateTime applicationDate) {
		this.applicationDate = applicationDate;
	}

	@PrePersist
	private void onPrePersist() {
		LocalDateTime now = LocalDateTime.now();
		this.changeDate = now;
		this.applicationDate = now;
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

	public String getApplicantStatus() {
		return applicantStatus;
	}

	public void setApplicantStatus(String applicantStatus) {
		this.applicantStatus = applicantStatus;
	}
}