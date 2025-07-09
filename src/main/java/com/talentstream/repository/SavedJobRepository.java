package com.talentstream.repository;

import java.util.List;
import java.util.Set;

import javax.transaction.Transactional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.talentstream.dto.GetJobDTO;
import com.talentstream.entity.Applicant;
import com.talentstream.entity.Job;
import com.talentstream.entity.SavedJob;

@Repository
public interface SavedJobRepository extends JpaRepository<SavedJob, Long> {

	List<SavedJob> findByApplicantId(long applicantId);

	List<SavedJob> findByJob(Job job);

	boolean existsByApplicantAndJob(Applicant applicant, Job job);

	SavedJob findByApplicantAndJob(Applicant applicant, Job job);

	@Query(value = "SELECT COUNT(*) FROM applicant_savedjob WHERE applicantregistration_id = :applicantId AND save_job_status = 'saved'", nativeQuery = true)
	long countByApplicantId(@Param("applicantId") long applicantId);

	boolean existsByApplicantIdAndJobId(long applicantId, long jobId);
     
	
//	@Query("SELECT sj.job.id FROM SavedJob sj " +
//		       "WHERE sj.applicant.id = :applicantId AND sj.saveJobStatus = 'saved'")
//	List<Long> findSavedJobIdsByApplicantId(long applicantId);
	
	  @Query("SELECT new com.talentstream.dto.GetJobDTO(" +
		       "sj.job.id, sj.job.minimumExperience, sj.job.maximumExperience, sj.job.jobTitle, " +
		       "sj.job.minSalary, sj.job.maxSalary, sj.job.employeeType, sj.job.industryType, " +
		       "sj.job.creationDate, sj.job.location, sj.job.jobRecruiter.companyname) " +
		       "FROM SavedJob sj " +
		       "WHERE sj.applicant.id = :applicantId " +
		       "ORDER BY sj.id DESC")
		Page<GetJobDTO> findByApplicantId(@Param("applicantId") long applicantId, Pageable pageable);

	@Modifying
	@Transactional
	@Query("DELETE FROM SavedJob sj WHERE sj.applicant.id = :applicantId AND sj.job.id = :jobId")
	int deleteByApplicantIdAndJobId(@Param("applicantId") Long applicantId, @Param("jobId") Long jobId);

	@Query("SELECT sj.job.id FROM SavedJob sj WHERE sj.applicant.id = :applicantId")

	Set<Long> findJobIdsByApplicantId(@Param("applicantId") long applicantId);
}
