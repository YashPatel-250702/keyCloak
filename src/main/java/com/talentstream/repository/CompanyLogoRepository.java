package com.talentstream.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.talentstream.entity.CompanyLogo;
import com.talentstream.entity.JobRecruiter;

@Repository
public interface CompanyLogoRepository extends JpaRepository<CompanyLogo, Long> {
	CompanyLogo findByJobRecruiterRecruiterId(long jobRecruiterId);
}
