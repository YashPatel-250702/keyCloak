package com.talentstream.entity;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Entity
public class HiredCandidateCount {
	
	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long Id;

	private Long hiredCount;

	public Long getId() {
		return Id;
	}

	public void setId(Long id) {
		Id = id;
	}

	public Long getHiredCount() {
		return hiredCount;
	}

	public void setHiredCount(Long hiredCount) {
		this.hiredCount = hiredCount;
	}

	public HiredCandidateCount(Long id, Long hiredCount) {
		Id = id;
		this.hiredCount = hiredCount;
	}

	public HiredCandidateCount() {
	
	}
	
	
	
}
