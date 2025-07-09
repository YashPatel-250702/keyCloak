package com.talentstream.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.talentstream.entity.ApplicantTest;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Repository
public interface ApplicantTestRepository extends JpaRepository<ApplicantTest, Long> {
    List<ApplicantTest> findByApplicantId(Long applicantId);

	Optional<ApplicantTest> findByApplicantIdAndTestName(Long applicantId, String testName);
	@Query("SELECT new map(" +
	           "MAX(CASE WHEN test.testName = 'General Aptitude Test' THEN test.testScore ELSE 0 END) AS aptitudeScore, " +
	           "MAX(CASE WHEN test.testName IN ('Technical Test', 'Technical') THEN test.testScore ELSE 0 END) AS technicalScore) " +
	           "FROM ApplicantTest test " +
	           "WHERE test.applicant.id = :applicantId")
	Map<String, Double> findTestScoresByApplicantId(@Param("applicantId") Long applicantId);


}
