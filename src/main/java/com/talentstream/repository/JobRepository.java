package com.talentstream.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.talentstream.dto.GetJobDTO;
import com.talentstream.entity.ApplicantSkills;
import com.talentstream.entity.Job;

@Repository
public interface JobRepository extends JpaRepository<Job, Long>, JpaSpecificationExecutor<Job> {
	@Query("SELECT DISTINCT j FROM Job j JOIN j.skillsRequired s WHERE " +
			"(:skillName is null or s.skillName = :skillName) or " +
			"(:jobTitle is null or j.jobTitle = :jobTitle) or " +
			"(:location is null or j.location = :location) or " +
			"(:industryType is null or j.industryType = :industryType) or " +
			"(:employeeType is null or j.employeeType = :employeeType) or " +
			"(:minimumQualification is null or j.minimumQualification = :minimumQualification) or " +
			"(:specialization is null or j.specialization = :specialization)")
	List<Job> searchJobs(
			@Param("skillName") String skillName,
			@Param("jobTitle") String jobTitle,
			@Param("location") String location,
			@Param("industryType") String industryType,
			@Param("employeeType") String employeeType,
			@Param("minimumQualification") String minimumQualification,
			@Param("specialization") String specialization

	);

	@Query("SELECT j FROM Job j " +
			"JOIN FETCH j.skillsRequired " + // Ensure skills are fetched eagerly
			"WHERE j.id = :jobId")
	Job findJobWithSkills(@Param("jobId") Long jobId);

	@Query("SELECT DISTINCT j FROM Job j " +
			"JOIN j.skillsRequired r " +
			"WHERE LOWER(r.skillName) IN :skillNames")
	List<Job> findBySkillsRequiredIgnoreCaseAndSkillNameIn(Set<String> skillNames);

	@Query("SELECT j FROM Job j WHERE j.jobRecruiter.id = :jobRecruiterId")
	List<Job> findByJobRecruiterId(@Param("jobRecruiterId") Long jobRecruiterId);

	@Query("SELECT COUNT(j) FROM Job j WHERE j.jobRecruiter.id = :recruiterId AND j.status = 'active'")
	long countJobsByRecruiterId(@Param("recruiterId") Long recruiterId);

	@Query("SELECT j FROM Job j JOIN j.skillsRequired s WHERE LOWER(s.skillName) LIKE LOWER(CONCAT('%', :skillName, '%'))")
	List<Job> findJobsBySkillNameIgnoreCase(@Param("skillName") String skillName);

	@Query("SELECT DISTINCT j FROM Job j JOIN j.skillsRequired s WHERE s.skillName = :skillName")
	Page<Job> findJobsBySkillName(String skillName, Pageable pageable);

	@Query("SELECT j FROM Job j WHERE j.alertCount > 0 AND j.recentApplicationDateTime >= :minDateTime AND j.jobRecruiter.recruiterId = :recruiterId")
	List<Job> findJobsWithAlertCountAndRecentDateTimeGreaterThanAndRecruiterId(
			@Param("minDateTime") LocalDateTime minDateTime,
			@Param("recruiterId") Long recruiterId);

	@Query("SELECT DISTINCT j, asj.saveJobStatus FROM Job j " +
			"LEFT JOIN SavedJob asj ON asj.job = j  AND asj.applicant.id = :applicantId " +
			"WHERE  " +
			"(j.promote = :promote)")
	List<Object[]> findByPromote(@Param("applicantId") long applicantId, @Param("promote") String promote);

	@Query("SELECT DISTINCT new com.talentstream.dto.GetJobDTO(" +
		       "j.id, j.minimumExperience, j.maximumExperience, j.jobTitle, j.minSalary, j.maxSalary, " +
		       "j.employeeType, j.industryType, j.creationDate, j.location, j.jobRecruiter.companyname) " +
		       "FROM Job j " +
		       "LEFT JOIN j.skillsRequired s " +
		       "WHERE j.status != 'inactive' " +
		       "AND j.id NOT IN :appliedJobIds " +
		       "AND j.id NOT IN :savedJobIds " +
		       "AND (" +
		       "  LOWER(j.specialization) = LOWER(:specialization) " +
		       "  OR j.minimumExperience = :experience " +
		       "  OR j.location IN :preferredLocations " +
		       "  OR LOWER(s.skillName) IN :skillNames" +
		       ") " +
		       "ORDER BY j.creationDate DESC")
		Page<GetJobDTO> GetRecomendedJobs(
		        @Param("skillNames") Set<String> skillNames,
		        @Param("preferredLocations") Set<String> preferredLocations,
		        @Param("experience") Integer experience,
		        @Param("specialization") String specialization,
		        @Param("appliedJobIds") Set<Long> appliedJobIds,
		        @Param("savedJobIds") Set<Long> savedJobIds,
		        Pageable pageable);



	@Query("SELECT j FROM Job j WHERE j.jobRecruiter.id = :jobRecruiterId AND j.status = :status")
	List<Job> findJobsByRecruiterAndStatus(@Param("jobRecruiterId") Long jobRecruiterId,
			@Param("status") String status);

	@Query("SELECT COUNT(j) FROM Job j WHERE j.jobRecruiter.id = :recruiterId AND j.status = 'inactive'")
	long countInActiveJobsByRecruiterId(@Param("recruiterId") Long recruiterId);

	@Query("SELECT new com.talentstream.dto.GetJobDTO(" +
		       "j.id, j.minimumExperience, j.maximumExperience, j.jobTitle, j.minSalary, j.maxSalary, " +
		       "j.employeeType, j.industryType, j.creationDate, j.location, j.jobRecruiter.companyname) " +
		       "FROM Job j WHERE j.id IN :jobIds ORDER BY j.id ASC")
		Page<GetJobDTO> findJobsByIds(@Param("jobIds") List<Long> jobIds, Pageable pageable);


	
	@Query("SELECT DISTINCT j.id " + "FROM Job j " + "LEFT JOIN j.skillsRequired s " + // Keep skills join but optimize
																						// filtering
			"WHERE j.status != 'inactive' " + "AND (LOWER(j.specialization) = LOWER(:specialization) "
			+ "OR j.minimumExperience = :experience " + "OR j.location IN :preferredLocations "
			+ "OR LOWER(s.skillName) IN :skillNames)")
	List<Long> findMatchingJobIds(
			@Param("skillNames") Set<String> skillNames,
			@Param("preferredLocations") Set<String> preferredLocations,
			@Param("experience") Integer experience,
			@Param("specialization") String specialization);

}
