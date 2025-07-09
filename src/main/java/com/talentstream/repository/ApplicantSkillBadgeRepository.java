package com.talentstream.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.talentstream.entity.ApplicantSkillBadge;

public interface ApplicantSkillBadgeRepository extends JpaRepository<ApplicantSkillBadge, Long> {
	
    List<ApplicantSkillBadge> findByApplicantId(Long applicantId);
  
    @Query("SELECT e FROM ApplicantSkillBadge e WHERE e.applicant.id = :applicantId AND e.flag = 'added'")
    List<ApplicantSkillBadge> findByApplicantIdAndFlagAdded(@Param("applicantId") Long applicantId);
    
    @Query("SELECT e FROM ApplicantSkillBadge e WHERE e.applicant.id = :applicantId AND e.flag = 'added' AND e.status = 'PASSED'")
    List<ApplicantSkillBadge> findPassedSkillBadgesByApplicantId(@Param("applicantId") Long applicantId);

	ApplicantSkillBadge findByApplicantIdAndSkillBadgeId(Long applicantId, Long skillBadgeId);
	
	void deleteByApplicantIdAndSkillBadgeId(Long applicantId, Long skillBadgeId);
	
	@Modifying
	@Query("UPDATE ApplicantSkillBadge e SET e.flag = 'removed' WHERE e.applicant.id = :applicantId AND e.skillBadge.id = :skillBadgeId")
	void updateFlagAsRemoved(@Param("applicantId") Long applicantId, @Param("skillBadgeId") Long skillBadgeId);
	
	@Modifying
	@Query("UPDATE ApplicantSkillBadge e SET e.flag = 'added' WHERE e.applicant.id = :applicantId AND e.skillBadge.id = :skillBadgeId")
	void updateFlagAsAdded(@Param("applicantId") Long applicantId, @Param("skillBadgeId") Long skillBadgeId);


}
