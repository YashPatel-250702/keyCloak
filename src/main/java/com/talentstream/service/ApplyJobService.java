package com.talentstream.service;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.mail.internet.InternetAddress;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import com.talentstream.dto.GetJobDTO;
import com.talentstream.dto.JobDTO;
import com.talentstream.dto.UpdateJobStatusDTO;
import com.talentstream.entity.Alerts;
import com.talentstream.entity.Applicant;
import com.talentstream.entity.ApplicantJobInterviewDTO;
import com.talentstream.entity.ApplicantProfile;
import com.talentstream.entity.ApplicantSkillBadge;
import com.talentstream.entity.ApplicantStatusHistory;
import com.talentstream.entity.AppliedApplicantInfo;
import com.talentstream.entity.AppliedApplicantInfoDTO;
import com.talentstream.entity.ApplyJob;
import com.talentstream.entity.Job;
import com.talentstream.entity.JobRecruiter;
import com.talentstream.entity.MatchTypes;
import com.talentstream.entity.RecuriterSkills;
import com.talentstream.entity.SavedJob;
import com.talentstream.exception.CustomException;
import com.talentstream.repository.AlertsRepository;
import com.talentstream.repository.ApplicantProfileRepository;
import com.talentstream.repository.ApplicantSkillBadgeRepository;
import com.talentstream.repository.ApplicantStatusHistoryRepository;
import com.talentstream.repository.ApplicantTestRepository;
import com.talentstream.repository.ApplyJobRepository;
import com.talentstream.repository.JobRecruiterRepository;
import com.talentstream.repository.JobRepository;
import com.talentstream.repository.RegisterRepository;
import com.talentstream.repository.SavedJobRepository;
import com.talentstream.repository.ScheduleInterviewRepository;

import jakarta.persistence.EntityNotFoundException;

@Service
public class ApplyJobService {
	@Autowired
	private ApplyJobRepository applyJobRepository;
	@Autowired
	private ScheduleInterviewRepository scheduleInterviewRepository;
	@Autowired
	private CompanyLogoService companyLogoService;
	@Autowired
	private JobRepository jobRepository;
	@Autowired
	private RegisterRepository applicantRepository;
	@Autowired
	private ApplicantStatusHistoryRepository statusHistoryRepository;
	@Autowired
	private JavaMailSender javaMailSender;
	@Autowired
	private AlertsRepository alertsRepository;
	@Autowired
	private JobRecruiterRepository jobRecruiterRepository;
	@Autowired
	private ApplicantProfileRepository applicantProfileRepo;
	@Autowired
	private SavedJobRepository savedJobRepository;
	@Autowired
	private ApplicantTestRepository applicantTestRepository;
	@Autowired
	private ViewJobService viewJobService;
	@Autowired
	private ApplicantSkillBadgeRepository applicantSkillBadgeRepository;


	// Marks the specified alert as seen by updating its status in the repository.
	public void markAlertAsSeen(long alertsId) {
		Optional<Alerts> alertOptional = alertsRepository.findById(alertsId);
		if (alertOptional.isPresent()) {
			Alerts alert = alertOptional.get();
			alert.setSeen(true);
			alertsRepository.save(alert);
		} else {
			throw new EntityNotFoundException("Alert with id " + alertsId + " not found.");
		}
	}

	// Allows an applicant to apply for a job, handling existing applications and
	// sending alerts if successful.
	public String ApplicantApplyJob(long applicantId, long jobId) {

		try {
			Applicant applicant = applicantRepository.findById(applicantId);
			Job job = jobRepository.findById(jobId).orElse(null);

			if (applicant == null || job == null) {
				throw new CustomException("Applicant ID or Job ID not found", HttpStatus.NOT_FOUND);
			}

			else {
				if (applyJobRepository.existsByApplicantAndJob(applicant, job)) {
					return "Job has already been applied by the applicant";
				} else {
					ApplyJob applyJob = new ApplyJob();
					applyJob.setApplicant(applicant);
					applyJob.setJob(job);
					applyJobRepository.save(applyJob);

					if (savedJobRepository.existsByApplicantIdAndJobId(applicant.getId(), job.getId())) {
						System.out.println("saved changed");
						SavedJob savedJob = savedJobRepository.findByApplicantAndJob(applicant, job);

						savedJob.setApplicant(applicant);
						savedJob.setSaveJobStatus("removed from saved");
						jobRepository.save(job);
						savedJob.setJob(job);
						savedJobRepository.save(savedJob);
					}

					job.setJobStatus("Already Applied");
					job.setAlertCount(job.getAlertCount() + 1);
					job.setRecentApplicationDateTime(LocalDateTime.now());
					job.setNewStatus("newapplicants");
					jobRepository.save(job);
					saveStatusHistory(applyJob, applyJob.getApplicantStatus());
					Job jobs = applyJob.getJob();
					if (jobs != null) {
						JobRecruiter recruiter = jobs.getJobRecruiter();

						if (recruiter != null) {
							String companyName = recruiter.getCompanyname();
							if (companyName != null) {
								String cN = recruiter.getCompanyname();

								String jobTitle = jobs.getJobTitle();
								recruiter.setAlertCount(recruiter.getAlertCount() + 1);
								jobRecruiterRepository.save(recruiter);
								sendAlerts(applyJob, applyJob.getApplicantStatus(), cN, jobTitle);
								return "Job applied successfully";
							}
						}
					}
					return "Company information not found for the given ApplyJob";
				}
			}
		} catch (CustomException ex) {
			throw ex;
		} catch (Exception e) {
			throw new CustomException("An error occurred while applying for the job: " + e.getMessage(),
					HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	// Counts the number of jobs applied for by the specified applicant, throwing an
	// error if the applicant is not found.
	public long countAppliedJobsForApplicant(long applicantId) {
		try {

			if (!applicantRepository.existsById(applicantId)) {

				throw new CustomException("Applicant not found", HttpStatus.NOT_FOUND);
			}

			return applyJobRepository.countByApplicantId(applicantId);
		} catch (CustomException e) {
			throw e;
		} catch (Exception e) {
			throw new CustomException("Error while counting applied jobs for the applicant",
					HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	// Increments the alert count for the specified applicant and saves the updated
	// count to the database.
	private void incrementAlertCount(Applicant applicant) {

		if (applicant != null) {
			int currentAlertCount = applicant.getAlertCount();
			applicant.setAlertCount(currentAlertCount + 1);
			applicantRepository.save(applicant);
		}
	}

	// Creates and saves an alert for the applicant and sends an email notification
	// regarding their application status.
	private void sendAlerts(ApplyJob applyJob, String applicantStatus, String cN, String jobTitle) {

		Alerts alerts = new Alerts();
		alerts.setApplyJob(applyJob);
		alerts.setApplicant(applyJob.getApplicant());
		alerts.setCompanyName(cN);
		alerts.setStatus(applicantStatus);
		alerts.setJobTitle(jobTitle);
		LocalDateTime currentDate = LocalDateTime.now();

		LocalDateTime currentChangeDateTime = currentDate;

		LocalDateTime updatedChangeDateTime = currentChangeDateTime
				.plusHours(5)
				.plusMinutes(30);
		alerts.setChangeDate(updatedChangeDateTime);
		alertsRepository.save(alerts);

		sendEmailToApplicant(applyJob.getApplicant().getEmail(), cN, applicantStatus, jobTitle);
	}

	// Sends an email notification to the applicant regarding their job application
	// status.
	private void sendEmailToApplicant(String toEmail, String cN, String applicantStatus, String jobTitle) {

		try {
			javax.mail.internet.MimeMessage message = javaMailSender.createMimeMessage();
			MimeMessageHelper helper = new MimeMessageHelper(message, true);

			helper.setFrom(new InternetAddress("no-reply@bitlabs.in", "bitLabs Jobs"));
			helper.setTo(toEmail);
			helper.setSubject("Your Application for " + jobTitle + " at " + cN + " has been Submitted");

			String content = "Dear Applicant,\n\n"
					+ "Thank you for applying for the position of " + jobTitle + " at " + cN
					+ " through bitLabs Jobs. We have received your application and it has been successfully submitted to the employer. "
					+ "\n\n"
					+ "What’s Next?\n\n"
					+ "1. Your application will be screened.\n"
					+ "2. If you are shortlisted, the employer will contact you directly for the next steps.\n"
					+ "3. Meanwhile, you can track your application status by logging into your bitLabs Jobs account & by clicking on applied jobs.\n\n"
					+ "Happy job searching! \n\n"
					+ "Regards\n"
					+ "The bitLabs Jobs Team.\n\n"
					+ "This is an auto-generated email. Please do not reply.";
			helper.setText(content);

			javaMailSender.send(message);
		} catch (Exception e) {

			e.printStackTrace();
		}
	}

	// Saves the status history of an application with the current date and status.
	private void saveStatusHistory(ApplyJob applyJob, String applicationStatus) {

		LocalDateTime currentDateTime = LocalDateTime.now();
		System.out.println("before addition " + currentDateTime);

		LocalDateTime updatedDateTime = currentDateTime.plus(Duration.ofHours(5).plusMinutes(30));
		System.out.println("after addition " + updatedDateTime);

		LocalDate updatedDate = updatedDateTime.toLocalDate();

		ApplicantStatusHistory statusHistory = new ApplicantStatusHistory();
		statusHistory.setApplyJob(applyJob);
		statusHistory.setStatus(applicationStatus);
		statusHistory.setChangeDate(updatedDate);
		statusHistoryRepository.save(statusHistory);
	}

	// Retrieves a list of applicants who have applied for a specific job by its ID.
	public List<ApplyJob> getAppliedApplicantsForJob(Long jobId) {
		try {
			return applyJobRepository.findByJobId(jobId);
		} catch (Exception e) {
			throw new CustomException("Failed to retrieve applied applicants for the job",
					HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	// Retrieves a list of job details for jobs applied to by a specific applicant.
	public Page<GetJobDTO> getAppliedJobsForApplicant(long applicantId, int page, int size) {
		try {
			Pageable pageable = PageRequest.of(page, size);
			Page<GetJobDTO> appliedJobsPage = applyJobRepository.findByApplicantId(applicantId, pageable);        
           
 
			return appliedJobsPage;
		} catch (Exception e) {
			throw new CustomException("Failed to get applied jobs for the applicant", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}
 
	// Retrieves and filters a list of applied applicants based on various criteria
	// and match types.
	public List<AppliedApplicantInfoDTO> getAppliedApplicants2(long jobRecruiterId, MatchTypes matchTypes, String name,
			String email, String mobileNumber, String jobTitle, String applicantStatus, Integer minimumExperience,
			String skillName, String minimumQualification, String location) {
		List<AppliedApplicantInfo> all1 = applyJobRepository.findAppliedApplicantsInfo(jobRecruiterId);

		List<AppliedApplicantInfoDTO> all = new ArrayList<>();

		System.out.println(matchTypes.getName());
		System.out.println(matchTypes.getMobilenumber());

		for (AppliedApplicantInfo appliedApplicantInfo : all1) {
			try {
				long id1 = appliedApplicantInfo.getId();
				ApplicantProfile applicantProfile = applicantProfileRepo.findByApplicantId(id1);
				AppliedApplicantInfoDTO dto1 = mapToDTO(appliedApplicantInfo);
				dto1.setExperience(applicantProfile.getExperience());
				String name1 = applicantProfile.getBasicDetails().getFirstName() + " "
						+ applicantProfile.getBasicDetails().getLastName();
				dto1.setName(name1);
				dto1.setMobilenumber(applicantProfile.getBasicDetails().getAlternatePhoneNumber());
				dto1.setMinimumQualification(applicantProfile.getQualification());
				all.add(dto1);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		List<AppliedApplicantInfoDTO> filteredList = null;
		try {
			filteredList = all.stream()
					.filter(applicant -> (name == null
							|| applyMatchType(applicant.getName(), name, matchTypes.getName(), "is")) &&
							(email == null
									|| applyMatchType(applicant.getEmail(), email, matchTypes.getEmail(), "contains"))
							&&
							(mobileNumber == null || applyMobileType(applicant.getMobilenumber(), mobileNumber,
									matchTypes.getMobilenumber(), "is"))
							&&
							(jobTitle == null || applyMatchType(applicant.getJobTitle(), jobTitle,
									matchTypes.getJobTitle(), "contains"))
							&&
							(applicantStatus == null || applyMatchType(applicant.getApplicantStatus(), applicantStatus,
									matchTypes.getApplicantStatus(), "contains"))
							&&

							(minimumQualification == null || applyMatchType(applicant.getMinimumQualification(),
									minimumQualification, matchTypes.getMinimumQualification(), "contains"))
							&&
							(location == null || applyMatchType(applicant.getLocation(), location,
									matchTypes.getLocation(), "contains"))
							&&
							(minimumExperience == null || applyExperienceMatchType(applicant.getExperience(),
									minimumExperience, matchTypes.getMinimumExperience(), "lessThan")))
					.collect(Collectors.toList());
		} catch (Exception e) {

			e.printStackTrace();
			filteredList = new ArrayList<>();
		}

		Set<Long> uniqueApplyJobIds = new HashSet<>();
		List<AppliedApplicantInfoDTO> uniqueList = new ArrayList<>();

		for (AppliedApplicantInfoDTO applicant : filteredList) {
			try {
				long applyJobId = applicant.getApplyjobid();
				if (!uniqueApplyJobIds.contains(applyJobId) && applyJobId >= 1) {
					uniqueApplyJobIds.add(applyJobId);
					uniqueList.add(applicant);
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return uniqueList;
	}

	// Checks if the string matches the filter based on the specified match type
	// (contains or is).
	private boolean applyMatchType(String value, String filterValue, String matchValue, String matchType) {
		if (matchValue == null) {
			return true;
		}
		if (matchValue.equalsIgnoreCase("contains")) {
			return value.toLowerCase().contains(filterValue.toLowerCase());
		} else if (matchValue.equalsIgnoreCase("is")) {
			return value.equalsIgnoreCase(filterValue);
		}
		return false;
	}

	// Checks if the mobile number matches the filter based on the specified match
	// type (contains or is).
	private boolean applyMobileType(String value, String filterValue, String matchValue, String matchType) {
		if (matchValue == null) {
			return true;
		}
		if (matchValue.equalsIgnoreCase("contains")) {
			return value.toLowerCase().contains(filterValue.toLowerCase());
		} else if (matchValue.equalsIgnoreCase("is")) {
			if (filterValue.length() == value.length()) {
				return value.equalsIgnoreCase(filterValue);
			} else {
				return false;
			}
		}
		return false;
	}

	// Evaluates if the experience value matches the specified filter based on the
	// defined match type (greaterThan, lessThan, or is).
	private boolean applyExperienceMatchType(String value1, int filterValue, String matchValue, String matchType) {
		int value = Integer.parseInt(value1.trim());
		if (matchValue == null) {
			return true;
		}
		if (matchValue.equalsIgnoreCase("greaterThan")) {
			return value > filterValue;
		} else if (matchValue.equalsIgnoreCase("lessThan")) {
			return value < filterValue;
		} else if (matchValue.equalsIgnoreCase("is")) {
			return value == filterValue;
		}
		return false;
	}

	// Retrieves applied applicants for a given job recruiter, mapping their
	// information into DTOs and organizing by unique keys.
	public Map<String, List<AppliedApplicantInfoDTO>> getAppliedApplicants(long jobRecruiterId) {

		List<AppliedApplicantInfo> appliedApplicants = applyJobRepository.findAppliedApplicantsInfo(jobRecruiterId);

		Map<String, AppliedApplicantInfoDTO> applicantMap = new HashMap<>();

		for (AppliedApplicantInfo appliedApplicantInfo : appliedApplicants) {

			String applicantKey = appliedApplicantInfo.getEmail() + "_" + appliedApplicantInfo.getApplyjobid();
			System.out.println("applicantKey " + applicantKey);
			AppliedApplicantInfoDTO dto;

			if (!applicantMap.containsKey(applicantKey)) {
				dto = mapToDTO(appliedApplicantInfo);
				try {

					ApplicantProfile applicantProfile = applicantProfileRepo
							.findByApplicantId(appliedApplicantInfo.getId());
					dto.setExperience(applicantProfile.getExperience());
					String name = applicantProfile.getBasicDetails().getFirstName() + " "
							+ applicantProfile.getBasicDetails().getLastName();
					dto.setName(name);
					dto.setMobilenumber(applicantProfile.getBasicDetails().getAlternatePhoneNumber());
					dto.setMinimumQualification(applicantProfile.getQualification());
					dto.setPreferredJobLocations(applicantProfile.getPreferredJobLocations());
					dto.setQualification(applicantProfile.getQualification());
					dto.setSpecialization(applicantProfile.getSpecialization());

					ResponseEntity<?> jobDetails = viewJobService.getJobDetailsForApplicantSkillMatch(dto.getJobId(),
							appliedApplicantInfo.getId());
					// Extract the body from the ResponseEntity
					Object responseBody = jobDetails.getBody();
					// Assuming the body is of type JobDetailsResponse (replace with actual class
					// name)
					if (responseBody instanceof JobDTO) {
						JobDTO jobDetailsResponse = (JobDTO) responseBody;

						dto.setMatchPercentage(jobDetailsResponse.getMatchPercentage());
						dto.setMatchedSkills(jobDetailsResponse.getMatchedSkills());
						dto.setNonMatchedSkills(jobDetailsResponse.getSkillsRequired());
						dto.setAdditionalSkills(jobDetailsResponse.getAdditionalSkills());

					} else {
						System.out.println("Unexpected response body type: " + responseBody.getClass().getName());
					}

					Map<String, Double> testScores = applicantTestRepository
							.findTestScoresByApplicantId(appliedApplicantInfo.getId());

					Double aptitudeScore = testScores.get("aptitudeScore");
					Double technicalScore = testScores.get("technicalScore");

					dto.setApptitudeScore(aptitudeScore != null ? aptitudeScore : 0.0);
					dto.setTechnicalScore(technicalScore != null ? technicalScore : 0.0);

					if (aptitudeScore != null && technicalScore != null && aptitudeScore >= 70.00
							&& technicalScore >= 70.00) {
						dto.setPreScreenedCondition("PreScreened");
					} else {
						dto.setPreScreenedCondition("NotPreScreened");
					}

					// Find applicant skills based on applicant ID
					List<ApplicantSkillBadge> applicantSkills = applicantSkillBadgeRepository
							.findPassedSkillBadgesByApplicantId(appliedApplicantInfo.getId());

					if (applicantSkills != null && !applicantSkills.isEmpty()) {
						// Use the already retrieved applicantSkills to set the DTO
						dto.setApplicantSkillBadges(applicantSkills);
					}

				} catch (Exception e) {
					e.printStackTrace();
				}
				applicantMap.put(applicantKey, dto);
			} else {
				dto = applicantMap.get(applicantKey);
			}

			// dto.addSkill(appliedApplicantInfo.getSkillName(),
			// appliedApplicantInfo.getMinimumExperience());
		}

		// Convert map values to list as the result requires a Map<String,
		// List<AppliedApplicantInfoDTO>>
		Map<String, List<AppliedApplicantInfoDTO>> result = new HashMap<>();
		for (Map.Entry<String, AppliedApplicantInfoDTO> entry : applicantMap.entrySet()) {
			result.put(entry.getKey(), Collections.singletonList(entry.getValue()));
		}
		return result;
	}

	// Retrieves and organizes applied applicants for a given job recruiter by job
	// ID, mapping details to DTOs.
	public Map<String, List<AppliedApplicantInfoDTO>> getAppliedApplicants1(long jobRecruiterId, long id) {
		List<AppliedApplicantInfo> appliedApplicants = applyJobRepository
				.findAppliedApplicantsInfoWithJobId(jobRecruiterId, id);
		Map<String, AppliedApplicantInfoDTO> applicantMap = new HashMap<>();

		for (AppliedApplicantInfo appliedApplicantInfo : appliedApplicants) {
			String applicantKey = appliedApplicantInfo.getEmail() + "_" + appliedApplicantInfo.getApplyjobid();

			if (!applicantMap.containsKey(applicantKey)) {
				try {
					long id1 = appliedApplicantInfo.getId();
					ApplicantProfile applicantProfile = applicantProfileRepo.findByApplicantId(id1);
					AppliedApplicantInfoDTO dto = mapToDTO(appliedApplicantInfo);
					dto.setExperience(applicantProfile.getExperience());
					String name = applicantProfile.getBasicDetails().getFirstName() + " "
							+ applicantProfile.getBasicDetails().getLastName();
					dto.setName(name);
					dto.setMobilenumber(applicantProfile.getBasicDetails().getAlternatePhoneNumber());
					dto.setMinimumQualification(applicantProfile.getQualification());
					// dto.addSkill(appliedApplicantInfo.getSkillName(),
					// appliedApplicantInfo.getMinimumExperience());
					dto.setPreferredJobLocations(applicantProfile.getPreferredJobLocations());
					dto.setQualification(applicantProfile.getQualification());
					dto.setSpecialization(applicantProfile.getSpecialization());

					ResponseEntity<?> jobDetails = viewJobService.getJobDetailsForApplicantSkillMatch(dto.getJobId(),
							appliedApplicantInfo.getId());
					// Extract the body from the ResponseEntity
					Object responseBody = jobDetails.getBody();
					// Assuming the body is of type JobDetailsResponse (replace with actual class
					// name)
					if (responseBody instanceof JobDTO) {
						JobDTO jobDetailsResponse = (JobDTO) responseBody;

						dto.setMatchPercentage(jobDetailsResponse.getMatchPercentage());
						dto.setMatchedSkills(jobDetailsResponse.getMatchedSkills());
						dto.setNonMatchedSkills(jobDetailsResponse.getSkillsRequired());
						dto.setAdditionalSkills(jobDetailsResponse.getAdditionalSkills());

					} else {
						System.out.println("Unexpected response body type: " + responseBody.getClass().getName());
					}

					Map<String, Double> testScores = applicantTestRepository
							.findTestScoresByApplicantId(appliedApplicantInfo.getId());

					Double aptitudeScore = testScores.get("aptitudeScore");
					Double technicalScore = testScores.get("technicalScore");

					dto.setApptitudeScore(aptitudeScore != null ? aptitudeScore : 0.0);
					dto.setTechnicalScore(technicalScore != null ? technicalScore : 0.0);

					if (aptitudeScore != null && technicalScore != null && aptitudeScore >= 70.00
							&& technicalScore >= 70.00) {
						dto.setPreScreenedCondition("PreScreened");
					} else {
						dto.setPreScreenedCondition("NotPreScreened");
					}

					// Find applicant skills based on applicant ID
					List<ApplicantSkillBadge> applicantSkills = applicantSkillBadgeRepository
							.findPassedSkillBadgesByApplicantId(appliedApplicantInfo.getId());

					if (applicantSkills != null && !applicantSkills.isEmpty()) {
						// Use the already retrieved applicantSkills to set the DTO
						dto.setApplicantSkillBadges(applicantSkills);
					}

					applicantMap.put(applicantKey, dto);
				} catch (Exception e) {
					e.printStackTrace();
				}
			} else {
				// AppliedApplicantInfoDTO existingDTO = applicantMap.get(applicantKey);
				try {
					// existingDTO.addSkill(appliedApplicantInfo.getSkillName(),
					// appliedApplicantInfo.getMinimumExperience());
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}

		Optional<Job> optionalJob = jobRepository.findById(id);
		if (optionalJob.isPresent()) {
			Job job = optionalJob.get();
			job.setNewStatus("oldApplicants");
			jobRepository.save(job);
		}

		Map<String, List<AppliedApplicantInfoDTO>> result = new HashMap<>();
		for (Map.Entry<String, AppliedApplicantInfoDTO> entry : applicantMap.entrySet()) {
			result.put(entry.getKey(), Collections.singletonList(entry.getValue()));
		}

		return result;
	}

	// Maps an AppliedApplicantInfo entity to an AppliedApplicantInfoDTO,
	// transferring relevant applicant details.
	private AppliedApplicantInfoDTO mapToDTO(AppliedApplicantInfo appliedApplicantInfo) {
		AppliedApplicantInfoDTO dto = new AppliedApplicantInfoDTO();
		dto.setApplyjobid(appliedApplicantInfo.getApplyjobid());
		dto.setName(appliedApplicantInfo.getName());
		dto.setJobId(appliedApplicantInfo.getJobId());
		dto.setId(appliedApplicantInfo.getId());
		dto.setEmail(appliedApplicantInfo.getEmail());
		dto.setMobilenumber(appliedApplicantInfo.getMobilenumber());
		dto.setJobTitle(appliedApplicantInfo.getJobTitle());
		dto.setApplicantStatus(appliedApplicantInfo.getApplicantStatus());
		dto.setMinimumExperience(appliedApplicantInfo.getMinimumExperience());
		dto.setMinimumQualification(appliedApplicantInfo.getMinimumQualification());
		Job job = jobRepository.findById(appliedApplicantInfo.getJobId()).orElse(null);
		if (job != null) {
			Set<RecuriterSkills> jobSkills = job.getSkillsRequired();
			if (jobSkills != null) {
				List<String> skills = jobSkills.stream()
						.filter(skill -> skill.getSkillName() != null) // Avoid null keys
						.map(RecuriterSkills::getSkillName)
						.collect(Collectors.toList());
				dto.setSkillName(skills);
			}
		}
		dto.setLocation(appliedApplicantInfo.getLocation());
		return dto;
	}

	// Updates the status of an applicant, logs the change, increments alert count,
	// saves status history, and sends alerts; throws EntityNotFoundException if
	// ApplyJob not found.
	public String updateApplicantStatus(Long applyJobId, String newStatus,String reason) {
		ApplyJob applyJob = applyJobRepository.findById(applyJobId)
				.orElseThrow(() -> new EntityNotFoundException("ApplyJob not found"));

		Job job = applyJob.getJob();
		if (job != null) {
			JobRecruiter recruiter = job.getJobRecruiter();
			if (recruiter != null) {
				String companyName = recruiter.getCompanyname();
				String jobTitle = job.getJobTitle();
				if (companyName != null) {
					applyJob.setApplicantStatus(newStatus);
					LocalDateTime currentDate = LocalDateTime.now();

					LocalDateTime currentChangeDateTime = currentDate;

					LocalDateTime updatedChangeDateTime = currentChangeDateTime
							.plusHours(5)
							.plusMinutes(30);
					applyJob.setApplicationDate(updatedChangeDateTime);
					applyJob.setChangeDate(updatedChangeDateTime);
					applyJob.setReason(reason);

					applyJobRepository.save(applyJob);

					incrementAlertCount(applyJob.getApplicant());

					saveStatusHistory(applyJob, applyJob.getApplicantStatus());

					//sendAlerts(applyJob, applyJob.getApplicantStatus(), companyName, jobTitle);
					return "Applicant status updated to: " + newStatus;
				}
			}
		}
		return "Company information not found for the given ApplyJob";
	}

	// Retrieves applicant job interview information by recruiter ID and status;
	// throws CustomException on failure.
	public List<ApplicantJobInterviewDTO> getApplicantJobInterviewInfoForRecruiterAndStatus(
			long recruiterId, String applicantStatus) {
		try {
			return scheduleInterviewRepository.getApplicantJobInterviewInfoByRecruiterAndStatus(recruiterId,
					applicantStatus);
		} catch (Exception e) {
			throw new CustomException("Failed to retrieve applicant job interview info",
					HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	// Counts job applicants for the specified recruiter ID; throws CustomException
	// on failure.
	public long countJobApplicantsByRecruiterId(Long recruiterId) {
		try {
			List<AppliedApplicantInfo> appliedApplicants = applyJobRepository.findAppliedApplicantsInfo(recruiterId);
			// Use a Set to ensure unique applicants based on email and job ID
			Set<String> uniqueApplicants = appliedApplicants.stream()
					.map(applicant -> applicant.getEmail() + "_" + applicant.getApplyjobid())
					.collect(Collectors.toSet());

			// Count the unique applicants
			return uniqueApplicants.size();
		} catch (Exception e) {
			throw new CustomException("Failed to count job applicants for the recruiter",
					HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	// Counts applicants with "Selected" status; throws CustomException on failure.
	public long countSelectedApplicants() {
		try {
			return applyJobRepository.countByApplicantStatus("Selected");
		} catch (Exception e) {
			throw new CustomException("Failed to count selected applicants", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	// Counts applicants with "Shortlisted" or "Interviewing" status; throws
	// CustomException on failure.
	public long countShortlistedAndInterviewedApplicants() {
		try {
			List<String> desiredStatusList = Arrays.asList("Shortlisted", "Interviewing");
			return applyJobRepository.countByApplicantStatusIn(desiredStatusList);
		} catch (Exception e) {
			throw new CustomException("Failed to count shortlisted and interviewed applicants",
					HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	// Retrieves the status history for the specified apply job ID, ordered by
	// change date in descending order.
	public List<ApplicantStatusHistory> getApplicantStatusHistory(long applyJobId) {

		return statusHistoryRepository.findByApplyJob_ApplyjobidOrderByChangeDateDesc(applyJobId);
	}

	// Retrieves alerts for the specified applicant ID, filtering out those with
	// "New" status and sorting by change date.
	public List<Alerts> getAlerts(long applicantId) {

		List<Alerts> alerts = alertsRepository.findByApplicantIdOrderByChangeDateDesc(applicantId);

		return alerts.stream()
				.filter(alert -> !"New".equals(alert.getApplyJob().getApplicantStatus()))
				.collect(Collectors.toList());
	}

	// Resets the alert count to 0 for the specified applicant ID; logs exceptions
	// on error.
	public void resetAlertCount(long applicantId) {

		try {

			Applicant applicant = applicantRepository.findById(applicantId);

			applicant.setAlertCount(0);
			applicantRepository.save(applicant);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// Counts applicants with "shortlisted" or "interviewing" status for the
	// specified recruiter ID; throws CustomException on error.
	public long countShortlistedAndInterviewedApplicants(long recruiterId) {
		try {
			List<String> desiredStatusList = Arrays.asList("shortlisted", "interviewing");
			return applyJobRepository.countShortlistedAndInterviewedApplicants(recruiterId, desiredStatusList);
		} catch (Exception e) {
			throw new CustomException("Failed to count shortlisted and interviewed applicants",
					HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	// Retrieves an ApplyJob entity for the specified job and applicant IDs; throws
	// CustomException if job/applicant not found or on error.
	public ApplyJob getByJobAndApplicant(Long jobId, Long applicantId) {
		try {
			Job job = jobRepository.findById(jobId).orElseThrow(() -> new EntityNotFoundException("Job not found"));
			Applicant applicant = applicantRepository.findById(applicantId);
			return applyJobRepository.findByJobAndApplicant(job, applicant);
		} catch (EntityNotFoundException e) {
			throw new CustomException("Job or Applicant not found", HttpStatus.NOT_FOUND);
		} catch (Exception e) {
			throw new CustomException("Error while retrieving ApplyJob", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	public String updateStatusByApplicantId(Long applicantId, Long applyJobId, String newStatus) {
		Applicant applicant = applicantRepository.findById(applicantId);
		if (applicant == null) {
			throw new CustomException("Applicant ID not found", HttpStatus.NOT_FOUND);
		}
		ApplyJob applyJob = applyJobRepository.findById(applyJobId)
				.orElseThrow(() -> new EntityNotFoundException("ApplyJob not found"));
		// to check whether that particular applicant is asscociated with that job
		if (applyJob.getApplicant().getId() != (applicantId)) {
			throw new CustomException("Applicant not applied for this job", HttpStatus.BAD_REQUEST);
		}
		Job job = applyJob.getJob();
		if (job != null) {
			JobRecruiter recruiter = job.getJobRecruiter();
			if (recruiter != null) {
				String companyName = recruiter.getCompanyname();
				String jobTitle = job.getJobTitle();
				if (companyName != null) {
					applyJob.setApplicantStatus(newStatus);
					LocalDateTime currentDate = LocalDateTime.now();

					LocalDateTime currentChangeDateTime = currentDate;

					LocalDateTime updatedChangeDateTime = currentChangeDateTime
							.plusHours(5)
							.plusMinutes(30);
					applyJob.setApplicationDate(updatedChangeDateTime);
					applyJob.setChangeDate(updatedChangeDateTime);

					applyJobRepository.save(applyJob);

					incrementAlertCount(applyJob.getApplicant());

					saveStatusHistory(applyJob, applyJob.getApplicantStatus());

					sendAlerts(applyJob, applyJob.getApplicantStatus(), companyName, jobTitle);
					return "Applicant status for applicant ID " + applicantId + " updated to: " + newStatus;
				}
			}
		}
		return "Company information not found for the given ApplyJob";
	}
}
