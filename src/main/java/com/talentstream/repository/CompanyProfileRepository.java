package com.talentstream.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.talentstream.dto.CompanyProfileDTO;
import com.talentstream.entity.CompanyProfile;
import com.talentstream.entity.JobRecruiter;

@Repository
public interface CompanyProfileRepository extends JpaRepository<CompanyProfile, Long> {

	JobRecruiter findByEmail(String username); 
	
	List<CompanyProfile> findByJobRecruiter(JobRecruiter jobRecruiter);
	CompanyProfile save(CompanyProfileDTO companyProfileDTO);
	@Query("SELECT CASE WHEN COUNT(c) > 0 THEN true ELSE false END FROM CompanyProfile c WHERE c.jobRecruiter.recruiterId = :recruiterId")
    boolean existsByJobRecruiterId(@Param("recruiterId") Long recruiterId);	
	CompanyProfile findByJobRecruiter_RecruiterId(Long jobRecruiterId);
	Optional<CompanyProfile>  findAllByJobRecruiter_RecruiterId(Long jobRecruiterId);
}
