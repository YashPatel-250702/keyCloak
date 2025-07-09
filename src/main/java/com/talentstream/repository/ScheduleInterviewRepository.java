package com.talentstream.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
 
import com.talentstream.entity.ApplicantJobInterviewDTO;
import com.talentstream.entity.ScheduleInterview;
 
@Repository
public interface ScheduleInterviewRepository extends JpaRepository<ScheduleInterview, Long> {
    // Define custom query methods if needed
	@Query("SELECT NEW com.talentstream.entity.ApplicantJobInterviewDTO(" +
	        "si.id, a.name, a.email, a.mobilenumber, j.jobTitle, si.timeAndDate, si.location, si.modeOfInterview, si.round, si.interviewLink, si.interviewPerson) " +
	        "FROM ScheduleInterview si " +
	        "INNER JOIN si.applyJob aj " +
	        "INNER JOIN aj.applicant a " +
	        "INNER JOIN aj.job j " +
	        "INNER JOIN j.jobRecruiter r " +
	        "WHERE r.recruiterId = :recruiterId " +
	        "AND aj.applicantStatus = :applicantStatus")
	List<ApplicantJobInterviewDTO> getApplicantJobInterviewInfoByRecruiterAndStatus(
	        @Param("recruiterId") long recruiterId,
	        @Param("applicantStatus") String applicantStatus);
	@Query("SELECT si FROM ScheduleInterview si " +
	           "WHERE DATE(si.timeAndDate) = CURRENT_DATE")
	    List<ScheduleInterview> findScheduleInterviewsForCurrentDate();
	@Query(value = "SELECT * FROM schedule_interview si WHERE si.apply_job_id IN (SELECT aj.applyjobid FROM ApplyJob aj WHERE aj.applicant_id = ?)", nativeQuery = true)
	List<ScheduleInterview> findByApplicantIdAndApplyJobId(Long applicantId, Long applyJobId);
 
}
 