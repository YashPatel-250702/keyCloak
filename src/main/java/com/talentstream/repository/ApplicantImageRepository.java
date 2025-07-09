package com.talentstream.repository;

import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.JpaRepository;
 
import com.talentstream.entity.Applicant;
import com.talentstream.entity.ApplicantImage;
@Repository
public interface ApplicantImageRepository extends JpaRepository<ApplicantImage, Long> {
 
	ApplicantImage findByApplicantId(long applicantId);
 
	ApplicantImage findById(Applicant applicant);
 
	boolean existsByApplicant(Applicant applicant);
 
	ApplicantImage findByApplicant(Applicant applicant);
	
}
