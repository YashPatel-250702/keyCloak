package com.talentstream.entity;

import java.time.LocalDateTime;

public class ApplicantJobInterviewDTO {
	private Long id;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	private String name;
	private String email;
	private String mobilenumber;
	private String jobTitle;
	private LocalDateTime timeAndDate;
	private String location;
	private String modeOfInterview;
	private int round;
	private String interviewLink;
	private String interviewPerson;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;

	}

	public String getMobilenumber() {
		return mobilenumber;

	}

	public void setMobilenumber(String mobilenumber) {
		this.mobilenumber = mobilenumber;

	}

	public String getJobTitle() {
		return jobTitle;

	}

	public void setJobTitle(String jobTitle) {
		this.jobTitle = jobTitle;

	}

	public LocalDateTime getTimeAndDate() {
		return timeAndDate;
	}

	public void setTimeAndDate(LocalDateTime timeAndDate) {
		this.timeAndDate = timeAndDate;
	}

	public String getLocation() {
		return location;
	}

	public void setLocation(String location) {
		this.location = location;
	}

	public String getModeOfInterview() {
		return modeOfInterview;
	}

	public void setModeOfInterview(String modeOfInterview) {
		this.modeOfInterview = modeOfInterview;
	}

	public int getRound() {
		return round;
	}

	public void setRound(int round) {
		this.round = round;
	}

	public String getInterviewLink() {
		return interviewLink;
	}

	public void setInterviewLink(String interviewLink) {
		this.interviewLink = interviewLink;
	}

	public String getInterviewPerson() {
		return interviewPerson;
	}

	public void setInterviewPerson(String interviewPerson) {
		this.interviewPerson = interviewPerson;
	}

	public ApplicantJobInterviewDTO(Long id, String name, String email, String mobilenumber, String jobTitle,
			LocalDateTime timeAndDate, String location, String modeOfInterview, int round, String interviewLink,
			String interviewPerson) {
		super();
		this.id = id;
		this.name = name;
		this.email = email;
		this.mobilenumber = mobilenumber;
		this.jobTitle = jobTitle;
		this.timeAndDate = timeAndDate;
		this.location = location;
		this.modeOfInterview = modeOfInterview;
		this.round = round;
		this.interviewLink = interviewLink;
		this.interviewPerson = interviewPerson;
	}

	public ApplicantJobInterviewDTO() {
		super();

	}

}