package com.talentstream.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
 
@Entity
public class ContactDetails {
 
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;
	 @Column(nullable = false)
	    private String name;
 
	    @Column(nullable = false)
	    private String subject;
 
	    @Column(nullable = false)
	    private String email;
 
	    @Column(nullable = false)
	    private String questions;
	public long getId() {
		return id;
	}
	public void setId(long id) {
		this.id = id;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getSubject() {
		return subject;
	}
	public void setSubject(String subject) {
		this.subject = subject;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getQuestions() {
		return questions;
	}
	public void setQuestions(String questions) {
		this.questions = questions;
	}
	@Override
	public String toString() {
		return "ContactDetails [id=" + id + ", name=" + name + ", subject=" + subject + ", email=" + email
				+ ", questions=" + questions + "]";
	}
	public ContactDetails(long id, String name, String subject, String email, String questions) {
		super();
		this.id = id;
		this.name = name;
		this.subject = subject;
		this.email = email;
		this.questions = questions;
	}
	public ContactDetails() {
		super();
	
	}
}