package com.talentstream.entity;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
 
@Entity
public class ApplicantImage {
		@Id
	    @GeneratedValue(strategy = GenerationType.IDENTITY)
		@Column(name = "id")
	    private long id;
		 	private String imagename;
		 	
	    @OneToOne(cascade = CascadeType.ALL)
	    @JoinColumn(name="applicantid", referencedColumnName = "id")
	    private Applicant applicant;
 
	    public Applicant getApplicant() {
	        return applicant;
	    }
 
	    public void setApplicant(Applicant applicant) {
	        this.applicant = applicant;
	    }
 
		public long getId() {
			return id;
		}
 
		public void setId(long id) {
			this.id = id;
		}
 
		public String getImagename() {
			return imagename;
		}
 
		public void setImagename(String imagename) {
			this.imagename = imagename;
		}
	    
	    
}