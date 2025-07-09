package com.talentstream.entity;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Embedded;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.OneToOne;

@Entity
public class ApplicantProfile {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int profileid;

	@Embedded
	private BasicDetails basicDetails;

	private String experience;

	private String qualification;

	private String specialization;

	@ElementCollection
	private Set<String> preferredJobLocations = new HashSet<>();

	@ManyToMany(fetch = FetchType.LAZY, cascade = { CascadeType.PERSIST, CascadeType.MERGE

	})
	@JoinTable(name = "applicant_profile_skills_required", joinColumns = @JoinColumn(name = "profileid"), inverseJoinColumns = @JoinColumn(name = "applicantskill_id"))
	private Set<ApplicantSkills> skillsRequired = new HashSet<>();

	@OneToOne(cascade = CascadeType.ALL)
	@JoinColumn(name = "applicantid", referencedColumnName = "id")
	private Applicant applicant;

	@Column(nullable = false)
	private String roles = "ROLE_JOBAPPLICANT";

	public int getProfileid() {
		return profileid;
	}

	public void setProfileid(int profileid) {
		this.profileid = profileid;
	}

	public BasicDetails getBasicDetails() {
		return basicDetails;
	}

	public void setBasicDetails(BasicDetails basicDetails) {
		this.basicDetails = basicDetails;
	}



	public Set<ApplicantSkills> getSkillsRequired() {
		return skillsRequired;
	}

	public void setSkillsRequired(Set<ApplicantSkills> skillsRequired) {
		this.skillsRequired = skillsRequired;
	}


	public Applicant getApplicant() {
		return applicant;
	}

	public void setApplicant(Applicant applicant) {
		this.applicant = applicant;
	}

	public String getRoles() {
		return roles;
	}

	public void setRoles(String roles) {
		this.roles = roles;
	}

	public String getExperience() {
		return experience;
	}

	public void setExperience(String experience) {
		this.experience = experience;
	}

	public String getQualification() {
		return qualification;
	}

	public void setQualification(String qualification) {
		this.qualification = qualification;
	}

	public String getSpecialization() {
		return specialization;
	}

	public void setSpecialization(String specialization) {
		this.specialization = specialization;
	}

	public Set<String> getPreferredJobLocations() {
		return preferredJobLocations;
	}

	public void setPreferredJobLocations(Set<String> preferredJobLocations) {
		this.preferredJobLocations = preferredJobLocations;
	}

}
