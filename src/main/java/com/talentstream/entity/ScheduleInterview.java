package com.talentstream.entity;

import java.time.LocalDateTime;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;

 
import com.fasterxml.jackson.annotation.JsonBackReference;
 
import javax.persistence.ManyToOne;
 
import javax.persistence.JoinColumn;
 
import javax.persistence.Id;
 
@Entity
public class ScheduleInterview {
	     @Id
	    @GeneratedValue(strategy = GenerationType.AUTO)
	    private Long id;
	    private String interviewTitle;
	    private String interviewPerson;
	    private String typeOfInterview;
	    private int round;
	    private LocalDateTime timeAndDate;
	    private String modeOfInterview;
	    private String location;
	    private String interviewLink;
	    @ManyToOne
	    @JsonBackReference
	    @JoinColumn(name = "apply_job_id")
	    private ApplyJob applyJob;
	public String getInterviewTitle() {
		return interviewTitle;
	}
	public void setInterviewTitle(String interviewTitle) {
		this.interviewTitle = interviewTitle;
	}
	public String getInterviewPerson() {
		return interviewPerson;
	}
	public void setInterviewPerson(String interviewPerson) {
		this.interviewPerson = interviewPerson;
	}
	public String getTypeOfInterview() {
		return typeOfInterview;
	}
	public void setTypeOfInterview(String typeOfInterview) {
		this.typeOfInterview = typeOfInterview;
	}
	public int getRound() {
		return round;
	}
	public void setRound(int round) {
		this.round = round;
	}
	public LocalDateTime getTimeAndDate() {
		return timeAndDate;
	}
	public void setTimeAndDate(LocalDateTime timeAndDate) {
		this.timeAndDate = timeAndDate;
	}
	public String getModeOfInterview() {
		return modeOfInterview;
	}
	public void setModeOfInterview(String modeOfInterview) {
		this.modeOfInterview = modeOfInterview;
	}
	public String getLocation() {
		return location;
	}
	public void setLocation(String location) {
		this.location = location;
	}
	public String getInterviewLink() {
		return interviewLink;
	}
	public void setInterviewLink(String interviewLink) {
		this.interviewLink = interviewLink;
	}
	 public Long getId() {
			return id;
		}
		public void setId(Long id) {
			this.id = id;
		}


public ApplyJob getApplyJob() {
		return applyJob;		}

		public Long getApplyJobId() {
	        return (applyJob != null) ? applyJob.getApplyjobid() : null;
	    }
		public void setApplyJob(ApplyJob applyJob) {
			this.applyJob = applyJob;
		}

	public ScheduleInterview() {
			super();
		}
	public ScheduleInterview(String interviewTitle, String interviewPerson, String typeOfInterview, int round,
			LocalDateTime timeAndDate, String modeOfInterview, String location, String interviewLink) {
		this.interviewTitle = interviewTitle;
		this.interviewPerson = interviewPerson;
		this.typeOfInterview = typeOfInterview;
		this.round = round;
		this.timeAndDate = timeAndDate;
		this.modeOfInterview = modeOfInterview;
		this.location = location;
		this.interviewLink = interviewLink;
	}
}