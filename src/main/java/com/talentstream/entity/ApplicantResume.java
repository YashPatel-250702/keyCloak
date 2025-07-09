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
public class ApplicantResume {
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "id")
    private long id;
	 	private String pdfname;
	 	
    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name="applicantid", referencedColumnName = "id")
    private Applicant applicant;
 
	public long getId() {
		return id;
	}
 
	public void setId(long id) {
		this.id = id;
	}
 
	public String getPdfname() {
		return pdfname;
	}
 
	public void setPdfname(String pdfname) {
		this.pdfname = pdfname;
	}
 
	public Applicant getApplicant() {
		return applicant;
	}
 
	public void setApplicant(Applicant applicant) {
		this.applicant = applicant;
	}
    
    
}
 