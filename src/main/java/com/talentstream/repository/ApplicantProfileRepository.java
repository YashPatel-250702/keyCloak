	package com.talentstream.repository;

import java.util.Optional;

import javax.transaction.Transactional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.talentstream.entity.ApplicantProfile;

@Repository
public interface ApplicantProfileRepository extends JpaRepository<ApplicantProfile, Integer> {

ApplicantProfile findByApplicantId(long applicantid);

@Query("SELECT a FROM ApplicantProfile a JOIN FETCH a.skillsRequired WHERE a.applicant.id = :applicantId")
Optional<ApplicantProfile> findByApplicantIdWithSkills(@Param("applicantId") long applicantId);


}