package com.talentstream.entity;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
 
@Entity
public class TeamMember {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    
    private String name;
    private String email;
    private String password;
    private String role;
 
    @ManyToOne
    @JoinColumn(name = "recruiter_id")
    private JobRecruiter recruiter;     
 
    public Long getId() {
		return id;
	}
 
	public void setId(Long id) {
		this.id = id;
	}
 
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
 
	public String getPassword() {
		return password;
	}
 
	public void setPassword(String password) {
		this.password = password;
	}
 
	public String getRole() {
		return role;
	}
 
	public void setRole(String role) {
		this.role = role;
	}
 
	public JobRecruiter getRecruiter() {
		return recruiter;
	}
 
	public void setRecruiter(JobRecruiter recruiter) {
		this.recruiter = recruiter;
	}
 
	public TeamMember() {
        
    }
 
	public TeamMember(Long id, String name, String email, String password, String role, JobRecruiter recruiter) {
		super();
		this.id = id;
		this.name = name;
		this.email = email;
		this.password = password;
		this.role = role;
		this.recruiter = recruiter;
	}
 
   
}
 