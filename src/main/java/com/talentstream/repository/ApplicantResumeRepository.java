package com.talentstream.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.talentstream.entity.Applicant;
import com.talentstream.entity.ApplicantResume;
 
public interface ApplicantResumeRepository extends JpaRepository<ApplicantResume, Long> {
 
	boolean existsByApplicant(Applicant applicant);
 
	ApplicantResume findById(Applicant applicant);
 
	ApplicantResume findByApplicantId(long applicantId);
 
	ApplicantResume findByApplicant(Applicant applicant);
 
}