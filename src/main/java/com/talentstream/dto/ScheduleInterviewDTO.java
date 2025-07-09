package com.talentstream.dto;

import java.time.LocalDateTime;

public class ScheduleInterviewDTO {
	private Long id;
    private String interviewTitle;
    private String interviewPerson;
    private String typeOfInterview;
    private int round;
    private LocalDateTime timeAndDate;
    private String modeOfInterview;
    private String location;
    private String interviewLink;
    private Long applyJobId;
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
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
	public Long getApplyJobId() {
		return applyJobId;
	}
	public void setApplyJobId(Long applyJobId) {
		this.applyJobId = applyJobId;
	} 
    
    
}
