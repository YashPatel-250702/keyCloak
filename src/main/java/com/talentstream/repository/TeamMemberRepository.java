package com.talentstream.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.talentstream.entity.Job;
import com.talentstream.entity.TeamMember;

@Repository
public interface TeamMemberRepository extends JpaRepository<TeamMember, Long> {

		//@Query("SELECT j FROM TeamMember j WHERE j.jobRecruiter.id = :jobRecruiterId")
	@Query(value = "SELECT * FROM team_member WHERE recruiter_id = :jobRecruiterId", nativeQuery = true)
	List<TeamMember> findByJobRecruiterId(@Param("jobRecruiterId") Long jobRecruiterId);
}
