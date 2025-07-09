package com.talentstream.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.talentstream.entity.JobRecruiter;

@Repository

public interface JobRecruiterRepository extends JpaRepository<JobRecruiter, Long> {
 
	JobRecruiter findByEmail(String email);  
 
	boolean existsByEmail(String email);	
	
	JobRecruiter findByRecruiterId(Long id);
 
	boolean existsByMobilenumber(String mobilenumber);
	
	JobRecruiter findByMobilenumber(String userMobile);
}
