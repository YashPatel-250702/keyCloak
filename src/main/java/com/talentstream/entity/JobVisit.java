package com.talentstream.entity;

import java.time.LocalDateTime;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;



@Entity
public class JobVisit {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    private long userId;
    private long jobId;
    
    @Column(nullable = false)
    private LocalDateTime visitedAt;
    public JobVisit() {}
	
    
	public JobVisit(long userId, long jobId, LocalDateTime visitedAt) {
		super();
		this.userId = userId;
		this.jobId = jobId;
		this.visitedAt = visitedAt;
	}


	public long getId() {
		return id;
	}
	public void setId(long id) {
		this.id = id;
	}
	public long getUserId() {
		return userId;
	}
	public void setUserId(long userId) {
		this.userId = userId;
	}
	public long getJobId() {
		return jobId;
	}
	public void setJobId(long jobId) {
		this.jobId = jobId;
	}
	public LocalDateTime getVisitedAt() {
		return visitedAt;
	}
	public void setVisitedAt(LocalDateTime visitedAt) {
		this.visitedAt = visitedAt;
	}
    
    
	
    
}

