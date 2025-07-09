package com.talentstream.controller;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.talentstream.dto.GetJobDTO;
import com.talentstream.dto.ScheduleInterviewDTO;
import com.talentstream.dto.UpdateJobStatusDTO;
import com.talentstream.entity.Alerts;
import com.talentstream.entity.Applicant;
import com.talentstream.entity.ApplicantJobInterviewDTO;
import com.talentstream.entity.ApplicantStatusHistory;
import com.talentstream.entity.AppliedApplicantInfoDTO;
import com.talentstream.entity.ApplyJob;
import com.talentstream.entity.MatchTypes;
import com.talentstream.entity.ScheduleInterview;
import com.talentstream.exception.CustomException;
import com.talentstream.repository.RegisterRepository;
import com.talentstream.service.ApplyJobService;
import com.talentstream.service.ScheduleInterviewService;

import jakarta.persistence.EntityNotFoundException;

@RestController
@RequestMapping("/applyjob")
public class ApplyJobController {

	final ModelMapper modelMapper = new ModelMapper();
	@Autowired
	private ApplyJobService applyJobService;
	@Autowired
	private ScheduleInterviewService scheduleInterviewService;

	@Autowired
	private RegisterRepository applicantRepository;
	
	

	private static final Logger logger = LoggerFactory.getLogger(ApplyJobController.class);

	@PostMapping("/applicants/applyjob/{applicantId}/{jobId}")
	public ResponseEntity<String> saveJobForApplicant(
			@PathVariable long applicantId,
			@PathVariable long jobId) {
		try {
			logger.info("Request received to save job for applicantId: {} and jobId: {}", applicantId, jobId);

			String result = applyJobService.ApplicantApplyJob(applicantId, jobId);
			logger.info("Job saved successfully for applicantId: {} and jobId: {}", applicantId, jobId);

			return ResponseEntity.ok(result);
		} catch (CustomException e) {
			logger.error("Error saving job for applicantId: {} and jobId: {}: {}", applicantId, jobId, e.getMessage());
			return ResponseEntity.status(e.getStatus()).body(e.getMessage());
		} catch (Exception e) {
			logger.error("Unexpected error saving job for applicantId: {} and jobId: {}", applicantId, jobId, e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An unexpected error occurred.");
		}
	}

	@GetMapping("/appliedapplicants/{jobId}")
	public ResponseEntity<List<ApplyJob>> getAppliedApplicantsForJob(@PathVariable Long jobId) {
		try {
			logger.info("Request received to get applied applicants for jobId: {}", jobId);
			List<ApplyJob> appliedApplicants = applyJobService.getAppliedApplicantsForJob(jobId);
			logger.info("Retrieved applied applicants successfully for jobId: {}", jobId);
			return ResponseEntity.ok(appliedApplicants);
		} catch (Exception e) {
			logger.error("Error getting applied applicants for jobId: {}: {}", jobId, e.getMessage());
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ArrayList<>());
		}
	}

	@GetMapping("/getAppliedJobs/{applicantId}")
	public ResponseEntity<List<GetJobDTO>> getAppliedJobsForApplicant(
			@PathVariable long applicantId,
			@RequestParam(defaultValue = "0") int page,
			@RequestParam(defaultValue = "10") int size) {
 
		try {
			logger.info("Request received to get applied jobs for applicantId: {}", applicantId);
			Page<GetJobDTO> appliedJobsPage = applyJobService.getAppliedJobsForApplicant(applicantId, page, size);
 
			if (appliedJobsPage.isEmpty()) {
				logger.info("No applied jobs found for applicantId: {}", applicantId);
				return ResponseEntity.noContent().build();
			}
			 List<GetJobDTO> savedJobsDTOList = appliedJobsPage.stream().map(job -> {
	            	GetJobDTO jobDTO = modelMapper.map(job, GetJobDTO.class);               
	                return jobDTO;
	            }).collect(Collectors.toList()); // Convert stream to list
 
			logger.info("Retrieved applied jobs successfully for applicantId: {}", applicantId);
			return ResponseEntity.ok(appliedJobsPage.getContent()); // Extract List from Page
		} catch (CustomException e) {
			logger.error("Error getting applied jobs for applicantId {}: {}", applicantId, e.getMessage());
			return ResponseEntity.status(e.getStatus()).body(Collections.emptyList());
		} catch (Exception e) {
			logger.error("Unexpected error getting applied jobs for applicantId: {}", applicantId, e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Collections.emptyList());
		}
	}
 
 
	@GetMapping("/countAppliedJobs/{applicantId}")
	public ResponseEntity<?> countAppliedJobsForApplicant(@PathVariable long applicantId) {
		try {
			logger.info("Request received to count applied jobs for applicantId: {}", applicantId);
			long count = applyJobService.countAppliedJobsForApplicant(applicantId);
			logger.info("Counted applied jobs successfully for applicantId: {}", applicantId);
			return ResponseEntity.ok(count);
		} catch (CustomException e) {
			logger.error("Error counting applied jobs for applicantId {}: {}", applicantId, e.getMessage());
			return ResponseEntity.status(e.getStatus()).body(e.getMessage());
		} catch (Exception e) {
			logger.error("Unexpected error counting applied jobs for applicantId: {}", applicantId, e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An unexpected error occurred.");
		}
	}

	@GetMapping("/recruiter/{jobRecruiterId}/appliedapplicants")
	public ResponseEntity<Map<String, List<AppliedApplicantInfoDTO>>> getAppliedApplicantsForRecruiter(
			@PathVariable long jobRecruiterId) {
		try {
			logger.info("Request received to get applied applicants for recruiterId: {}", jobRecruiterId);
			Map<String, List<AppliedApplicantInfoDTO>> appliedApplicantsMap = applyJobService
					.getAppliedApplicants(jobRecruiterId);
			logger.info("Retrieved applied applicants successfully for recruiterId: {}", jobRecruiterId);
			return ResponseEntity.ok(appliedApplicantsMap);
		} catch (CustomException e) {
			logger.error("Error getting applied applicants for recruiterId {}: {}", jobRecruiterId, e.getMessage());
			return ResponseEntity.status(e.getStatus()).body(new HashMap<>());
		} catch (Exception e) {
			logger.error("Unexpected error getting applied applicants for recruiterId: {}", jobRecruiterId, e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new HashMap<>());
		}
	}

	@PostMapping("/recruiter/{jobRecruiterId}/appliedapplicants1")
	public ResponseEntity<List<AppliedApplicantInfoDTO>> getAppliedApplicantsForRecruiter(
			@PathVariable long jobRecruiterId,
			@RequestParam(required = false) String name,
			@RequestParam(required = false) String email,
			@RequestParam(required = false) String mobileNumber,
			@RequestParam(required = false) String jobTitle,
			@RequestParam(required = false) String applicantStatus,
			@RequestParam(required = false) Integer minimumExperience,
			@RequestParam(required = false) String skillName,
			@RequestParam(required = false) String minimumQualification,
			@RequestParam(required = false) String location,
			@RequestBody MatchTypes matchTypes) {
		try {
			logger.info("Request received to get applied applicants for recruiterId: {}", jobRecruiterId);
			List<AppliedApplicantInfoDTO> appliedApplicants = applyJobService.getAppliedApplicants2(jobRecruiterId,
					matchTypes, name, email, mobileNumber, jobTitle, applicantStatus, minimumExperience, skillName,
					minimumQualification, location);
			logger.info("Retrieved applied applicants successfully for recruiterId: {}", jobRecruiterId);
			return ResponseEntity.ok(appliedApplicants);
		} catch (CustomException e) {
			logger.error("Error getting applied applicants for recruiterId {}: {}", jobRecruiterId, e.getMessage());
			return ResponseEntity.status(e.getStatus()).body(null);
		} catch (Exception e) {
			logger.error("Unexpected error getting applied applicants for recruiterId: {}", jobRecruiterId, e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
		}
	}

	@GetMapping("/recruiter/{jobRecruiterId}/appliedapplicants/{id}")
	public ResponseEntity<Map<String, List<AppliedApplicantInfoDTO>>> getAppliedApplicantsForRecruiter1(
			@PathVariable long jobRecruiterId, @PathVariable long id) {
		try {
			logger.info("Request received to get applied applicants for recruiterId: {} and id: {}", jobRecruiterId,
					id);
			Map<String, List<AppliedApplicantInfoDTO>> appliedApplicantsMap = applyJobService
					.getAppliedApplicants1(jobRecruiterId, id);
			logger.info("Retrieved applied applicants successfully for recruiterId: {} and id: {}", jobRecruiterId, id);
			return ResponseEntity.ok(appliedApplicantsMap);
		} catch (CustomException e) {
			logger.error("Error getting applied applicants for recruiterId {} and id {}: {}", jobRecruiterId, id,
					e.getMessage());
			return ResponseEntity.status(e.getStatus()).body(new HashMap<>());
		} catch (Exception e) {
			logger.error("Unexpected error getting applied applicants for recruiterId {} and id {}: {}", jobRecruiterId,
					id, e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new HashMap<>());
		}
	}

	@PostMapping("/scheduleInterview/{applyJobId}")
	public ResponseEntity<Void> createScheduleInterview(
			@PathVariable Long applyJobId,
			@RequestBody ScheduleInterviewDTO scheduleInterviewDTO) {
		try {
			logger.info("Request received to create schedule interview for applyJobId: {}", applyJobId);
			ScheduleInterview scheduleInterview = modelMapper.map(scheduleInterviewDTO, ScheduleInterview.class);
			ScheduleInterviewDTO createdInterview = scheduleInterviewService.createScheduleInterview(applyJobId,
					scheduleInterview);

			return createdInterview != null ? ResponseEntity.ok().build() : ResponseEntity.badRequest().build();
		} catch (Exception e) {
			logger.error("Unexpected error creating schedule interview for applyJobId: {}", applyJobId, e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
		}
	}


	
	
	@PutMapping("/recruiters/applyjob-update-status/{applyJobId}")
	public ResponseEntity<String> updateApplicantStatus(
			@PathVariable Long applyJobId,@RequestBody UpdateJobStatusDTO  dto) {
		try {
			logger.info("Request received to update applicant status for applyJobId: {} to status: {}", applyJobId);
			String updateMessage = applyJobService.updateApplicantStatus(applyJobId,dto.getNewStatus(),dto.getReason());
			logger.info("Applicant status updated successfully for applyJobId: {} to status: {}", applyJobId);
			return ResponseEntity.ok(updateMessage);
		} catch (CustomException e) {
			logger.error("Error updating applicant status for applyJobId {}: {}", applyJobId, e.getMessage());
			return ResponseEntity.status(e.getStatus()).body(e.getMessage());
		} catch (Exception e) {
			logger.error("Unexpected error updating applicant status for applyJobId {}: {}", applyJobId, e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An unexpected error occurred.");
		}
	}

	@GetMapping("/recruiter/{recruiterId}/interviews/{status}")
	public ResponseEntity<List<ApplicantJobInterviewDTO>> getApplicantJobInterviewInfo(
			@PathVariable("recruiterId") long recruiterId,
			@PathVariable("status") String status) {
		try {
			logger.info("Request received to get applicant job interview info for recruiterId: {} with status: {}",
					recruiterId, status);
			List<ApplicantJobInterviewDTO> interviewInfo = applyJobService
					.getApplicantJobInterviewInfoForRecruiterAndStatus(recruiterId, status);
			logger.info("Retrieved applicant job interview info successfully for recruiterId: {} with status: {}",
					recruiterId, status);
			return ResponseEntity.ok(interviewInfo);
		} catch (CustomException e) {
			logger.error("Error getting applicant job interview info for recruiterId {} with status {}: {}",
					recruiterId, status, e.getMessage());
			return ResponseEntity.status(e.getStatus()).body(new ArrayList<>());
		} catch (Exception e) {
			logger.error("Unexpected error getting applicant job interview info for recruiterId {} with status {}: {}",
					recruiterId, status, e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ArrayList<>());
		}
	}

	@GetMapping("/recruiters/applyjobapplicantscount/{recruiterId}")
	public ResponseEntity<Long> countJobApplicantsByRecruiterId(@PathVariable Long recruiterId) {
		try {
			logger.info("Request received to count job applicants by recruiterId: {}", recruiterId);
			long count = applyJobService.countJobApplicantsByRecruiterId(recruiterId);
			logger.info("Counted job applicants successfully by recruiterId: {}", recruiterId);
			return ResponseEntity.ok(count);
		} catch (CustomException e) {
			logger.error("Error counting job applicants by recruiterId {}: {}", recruiterId, e.getMessage());
			return ResponseEntity.status(e.getStatus()).body(0L);
		} catch (Exception e) {
			logger.error("Unexpected error counting job applicants by recruiterId {}: {}", recruiterId, e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(0L);
		}
	}

	@GetMapping("/recruiters/selected/count")
	public ResponseEntity<Long> countSelectedApplicants() {

		try {
			logger.info("Request received to count selected applicants");
			long count = applyJobService.countSelectedApplicants();
			logger.info("Counted selected applicants successfully");
			return ResponseEntity.ok(count);
		} catch (CustomException e) {
			logger.error("Error counting selected applicants: {}", e.getMessage());
			return ResponseEntity.status(e.getStatus()).body(0L);
		} catch (Exception e) {
			logger.error("Unexpected error counting selected applicants: {}", e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(0L);
		}
	}

	@GetMapping("/recruiters/countShortlistedAndInterviewed")
	public ResponseEntity<Long> countShortlistedAndInterviewedApplicants() {
		try {
			logger.info("Request received to count shortlisted and interviewed applicants");
			long count = applyJobService.countShortlistedAndInterviewedApplicants();
			logger.info("Counted shortlisted and interviewed applicants successfully");
			return ResponseEntity.ok(count);
		} catch (CustomException e) {
			logger.error("Error counting shortlisted and interviewed applicants: {}", e.getMessage());
			return ResponseEntity.status(e.getStatus()).body(0L);
		} catch (Exception e) {
			logger.error("Unexpected error counting shortlisted and interviewed applicants: {}", e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(0L);
		}
	}

	@GetMapping("/current-date")
	public ResponseEntity<List<ScheduleInterviewDTO>> getScheduleInterviewsForCurrentDate() {
		try {
			logger.info("Request received to get schedule interviews for current date");
			List<ScheduleInterview> scheduleInterviews = scheduleInterviewService.getScheduleInterviewsForCurrentDate();

			if (scheduleInterviews.isEmpty()) {
				logger.info("No schedule interviews found for the current date");
				return ResponseEntity.noContent().build();
			}
			List<ScheduleInterviewDTO> scheduleInterviewDTOs = scheduleInterviews.stream()
					.map(interview -> modelMapper.map(interview, ScheduleInterviewDTO.class))
					.collect(Collectors.toList());
			logger.info("Retrieved schedule interviews for the current date successfully");
			return ResponseEntity.ok(scheduleInterviewDTOs);
		} catch (CustomException e) {
			logger.error("Error getting schedule interviews for the current date: {}", e.getMessage());
			return ResponseEntity.status(e.getStatus()).body(new ArrayList<>());
		} catch (Exception e) {
			logger.error("Unexpected error getting schedule interviews for the current date: {}", e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ArrayList<>());
		}
	}

	@GetMapping("/getScheduleInterviews/applicant/{applyJobId}/{applicantId}")
	public ResponseEntity<List<ScheduleInterviewDTO>> getScheduleInterviews(
			@PathVariable Long applicantId, @PathVariable Long applyJobId) {
		try {
			logger.info("Request received to get schedule interviews for applicant {} and job {}", applicantId,
					applyJobId);
			List<ScheduleInterview> scheduleInterviews = scheduleInterviewService
					.getScheduleInterviewsByApplicantAndApplyJob(applicantId, applyJobId);

			if (scheduleInterviews.isEmpty()) {
				logger.info("No schedule interviews found for applicant {} and job {}", applicantId, applyJobId);
				return ResponseEntity.noContent().build();
			}

			List<ScheduleInterviewDTO> scheduleInterviewDTOs = scheduleInterviews.stream()
					.map(interview -> modelMapper.map(interview, ScheduleInterviewDTO.class))
					.collect(Collectors.toList());
			logger.info("Retrieved schedule interviews successfully for applicant {} and job {}", applicantId,
					applyJobId);
			return ResponseEntity.ok(scheduleInterviewDTOs);
		} catch (CustomException e) {
			logger.error("Error getting schedule interviews for applicant {} and job {}: {}", applicantId, applyJobId,
					e.getMessage());
			return ResponseEntity.status(e.getStatus()).body(new ArrayList<>());
		} catch (Exception e) {
			logger.error("Unexpected error getting schedule interviews for applicant {} and job {}: {}", applicantId,
					applyJobId, e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ArrayList<>());
		}
	}

	@GetMapping("/recruiters/applyjob-status-history/{applyJobId}")
	public ResponseEntity<List<ApplicantStatusHistory>> getApplicantStatusHistory(@PathVariable long applyJobId) {
		try {
			logger.info("Request received to get applicant status history for apply job {}", applyJobId);
			List<ApplicantStatusHistory> statusHistory = applyJobService.getApplicantStatusHistory(applyJobId);
			logger.info("Retrieved applicant status history successfully for apply job {}", applyJobId);
			return ResponseEntity.ok(statusHistory);
		} catch (EntityNotFoundException e) {
			// TODO: handle exception
			logger.error("Applicant status history not found for apply job {}: {}", applyJobId, e.getMessage());
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
		} catch (Exception e) {
			// TODO: handle exception
			logger.error("Unexpected error getting applicant status history for apply job {}: {}", applyJobId, e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
		}
	}

	@GetMapping("/applicant/job-alerts/{applicantId}")
	public ResponseEntity<List<Alerts>> getAlerts(@PathVariable long applicantId) {
		try {
			logger.info("Request received to get job alerts for applicant {}", applicantId);
			List<Alerts> notifications = applyJobService.getAlerts(applicantId);
			// Reset alertCount to zero when fetching alerts
			applyJobService.resetAlertCount(applicantId);
			logger.info("Retrieved job alerts successfully for applicant {}", applicantId);
			return ResponseEntity.ok(notifications);
		} catch (EntityNotFoundException e) {
			// TODO: handle exception
			logger.error("Job alerts not found for applicant {}: {}", applicantId, e.getMessage());
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
		} catch (Exception e) {
			// TODO: handle exception
			logger.error("Unexpected error getting job alerts for applicant {}: {}", applicantId, e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
		}
	}

	@GetMapping("/applicants/{applicantId}/unread-alert-count")
	public ResponseEntity<Integer> getUnreadAlertCount(@PathVariable long applicantId) {
		try {
			logger.info("Request received to get unread alert count for applicant {}", applicantId);
			Applicant applicant = applicantRepository.findById(applicantId);
			if (applicant != null) {
				int unreadAlertCount = applicant.getAlertCount();
				logger.info("Retrieved unread alert count successfully for applicant {}: {}", applicantId,
						unreadAlertCount);
				return ResponseEntity.ok(unreadAlertCount);
			} else {
				logger.warn("Applicant not found with ID {}", applicantId);
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
			}
		} catch (Exception e) {
			logger.error("Unexpected error getting unread alert count for applicant {}: {}", applicantId, e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
		}
	}

	@GetMapping("/recruiters/countShortlistedAndInterviewed/{recruiterId}")
	public ResponseEntity<Long> countShortlistedAndInterviewedApplicants(@PathVariable Long recruiterId) {
		try {
			logger.info("Request received to count shortlisted and interviewed applicants for recruiter {}",
					recruiterId);
			long count = applyJobService.countShortlistedAndInterviewedApplicants(recruiterId);
			logger.info("Counted shortlisted and interviewed applicants successfully for recruiter {}", recruiterId);
			return ResponseEntity.ok(count);
		} catch (CustomException e) {
			logger.error("Error counting shortlisted and interviewed applicants for recruiter {}: {}", recruiterId,
					e.getMessage());
			return ResponseEntity.status(e.getStatus()).body(0L);
		} catch (Exception e) {
			logger.error("Unexpected error counting shortlisted and interviewed applicants for recruiter {}: {}",
					recruiterId, e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(0L);
		}
	}

	@DeleteMapping("/scheduleInterview/{scheduleInterviewId}")
	public ResponseEntity<String> deleteScheduledInterview(@PathVariable Long scheduleInterviewId) {
		try {
			logger.info("Request received to delete scheduled interview with ID {}", scheduleInterviewId);
			scheduleInterviewService.deleteScheduledInterview(scheduleInterviewId);
			logger.info("Scheduled interview with ID {} deleted successfully", scheduleInterviewId);
			return ResponseEntity.ok("Interview cancelled successfully");
		} catch (EntityNotFoundException e) {
			logger.warn("Scheduled interview with ID {} not found", scheduleInterviewId);
			return ResponseEntity.notFound().build();
		} catch (Exception e) {

			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();

		}

	}

	@PutMapping("/applicant/mark-alert-as-seen/{alertsId}")
	public ResponseEntity<String> markAlertAsSeen(@PathVariable long alertsId) {
		try {
			applyJobService.markAlertAsSeen(alertsId);
			return ResponseEntity.ok("Alert marked as seen successfully.");
		} catch (EntityNotFoundException e) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Alert with id " + alertsId + " not found.");
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to mark alert as seen.");
		}
	}

	@PutMapping("/recruiters/applicant/{applicantId}/applyjob-update-status/{applyJobId}/{newStatus}")
	public ResponseEntity<String> updateApplicantstatus(@PathVariable Long applicantId, @PathVariable Long applyJobId,
			@PathVariable String newStatus) {
		try {
			logger.info("Received request to update applicantstatus for applyJobId:{} of applicantId: {} to status :{}",
					applyJobId, applicantId, newStatus);
			String updatedMessage = applyJobService.updateStatusByApplicantId(applicantId, applyJobId, newStatus);
			logger.info("Applicant status updated sucessfully for applyJobId:{} of applicantId:{} to status :{}",
					applyJobId, applicantId, newStatus);
			return ResponseEntity.ok(updatedMessage);
		} catch (CustomException ce) {
			logger.error("error while updating applicant status for applicant id {}:{}", applicantId, ce.getMessage());
			return ResponseEntity.status(ce.getStatus()).body(ce.getMessage());
		} catch (Exception e) {
			logger.error("Unexpected error while updating applicantstatus for applyJobId:{} of this applicantId {}:{}",
					applyJobId, applicantId, e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An unexpected error occurred.");
		}
	}

}
