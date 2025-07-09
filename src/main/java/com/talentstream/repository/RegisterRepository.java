package com.talentstream.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.talentstream.entity.Applicant;

@Repository
public interface RegisterRepository extends JpaRepository<Applicant,Integer> {
	Applicant  findByEmail(String email);
	boolean existsByEmail(String email);	
	Applicant getApplicantById(long applicantid);
	Applicant findById(long id);
	boolean existsByMobilenumber(String mobilenumber);
	boolean existsById(long applicantId);
	Applicant findByMobilenumber(String userMobile);
	List<Applicant> findAllByResumeId(String string);
 
}
