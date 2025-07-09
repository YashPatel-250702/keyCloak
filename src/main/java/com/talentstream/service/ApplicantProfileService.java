package com.talentstream.service;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.Set;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import com.talentstream.exception.CustomException;
import com.talentstream.dto.ApplicantProfileDTO;
import com.talentstream.dto.ApplicantProfileViewDTO;
import com.talentstream.dto.BasicDetailsDTO;
import com.talentstream.dto.JobDTO;
import com.talentstream.entity.Applicant;
import com.talentstream.entity.ApplicantProfile;
import com.talentstream.entity.ApplicantProfileUpdateDTO;
import com.talentstream.entity.ApplicantSkillBadge;
import com.talentstream.entity.ApplicantSkills;
import com.talentstream.entity.Job;
import com.talentstream.entity.RecuriterSkills;
import com.talentstream.entity.SkillBadge;
import com.talentstream.repository.ApplicantProfileRepository;
import com.talentstream.repository.ApplicantSkillBadgeRepository;
import com.talentstream.repository.ApplicantSkillsRepository;
import com.talentstream.repository.ApplicantTestRepository;
import com.talentstream.repository.JobRepository;
import com.talentstream.repository.RegisterRepository;
import com.talentstream.repository.SkillBadgeRepository;

import javax.persistence.EntityNotFoundException;
import javax.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class ApplicantProfileService {
	private final ApplicantProfileRepository applicantProfileRepository;
	private final RegisterRepository applicantService;

	@Autowired
	private ApplicantSkillsRepository applicantSkillsRepository;
	
	@Autowired
    private SkillBadgeRepository skillBadgeRepository;
	
	@Autowired
    private ApplicantSkillBadgeRepository applicantSkillBadgeRepository;
	
	@Autowired
	private JobRepository  jobRepository;
	
	@Autowired
	private ApplicantTestRepository applicantTestRepository;
	
	private static final Logger logger = LoggerFactory.getLogger(ApplicantProfileService.class);

	@Autowired
	public ApplicantProfileService(ApplicantProfileRepository applicantProfileRepository,
			RegisterRepository applicantService) {
		this.applicantProfileRepository = applicantProfileRepository;
		this.applicantService = applicantService;

	}

	public String createOrUpdateApplicantProfile(long applicantId, ApplicantProfileDTO applicantProfileDTO)
			throws IOException {
		Applicant applicant = applicantService.getApplicantById(applicantId);
		if (applicant == null)
			throw new CustomException("Applicant not found for ID: " + applicantId, HttpStatus.NOT_FOUND);
		else {
			ApplicantProfile existingProfile = applicantProfileRepository.findByApplicantId(applicantId);
			if (existingProfile == null) {
				ApplicantProfile applicantProfile = convertDTOToEntity(applicantProfileDTO);
				applicantProfile.setApplicant(applicant);
				applicantProfileRepository.save(applicantProfile);
				return "profile saved sucessfully";
			} else {
				throw new CustomException("Profile for this applicant already exists", HttpStatus.BAD_REQUEST);
			}
		}
	}

	// Retrieves the applicant's profile as a view DTO; throws
	// EntityNotFoundException if applicant is not found.
	public ApplicantProfileViewDTO getApplicantProfileViewDTO(long applicantId) {
		Applicant applicant = applicantService.findById(applicantId);
		ApplicantProfile applicantProfile = null;
		if (applicant == null)
			throw new EntityNotFoundException("Applicant not found with id: " + applicantId);

		try {
			applicantProfile = applicantProfileRepository.findByApplicantId(applicantId);
		} catch (Exception e) {
			return convertToDTO(applicant, applicantProfile);
		}

		return convertToDTO(applicant, applicantProfile);
	}

	// Converts applicant and profile entities to a view DTO.
	private ApplicantProfileViewDTO convertToDTO(Applicant applicant, ApplicantProfile applicantProfile) {
		ApplicantProfileViewDTO dto = new ApplicantProfileViewDTO();
		if (applicantProfile == null) {
			dto.setApplicant(applicant);
		} else {
			dto.setApplicant(applicant);
			dto.setBasicDetails(applicantProfile.getBasicDetails());
			Set<ApplicantSkills> unmatchedSkills = applicantProfile.getSkillsRequired().stream()
				    .filter(skill -> 
				        applicantProfile.getApplicant().getApplicantSkillBadges().stream()
				            .noneMatch(badge -> 
				                badge.getSkillBadge().getName().trim().equalsIgnoreCase(skill.getSkillName().trim()) 
				                && !badge.getFlag().equalsIgnoreCase("removed") // Exclude badges with flag 'removed'
				            )
				    )
				    .collect(Collectors.toSet()); 

			dto.setSkillsRequired(unmatchedSkills);
			dto.setExperience(applicantProfile.getExperience());
			dto.setQualification(applicantProfile.getQualification());
			dto.setSpecialization(applicantProfile.getSpecialization());
			dto.setPreferredJobLocations(applicantProfile.getPreferredJobLocations());
		}
		return dto;
	}


	public ApplicantProfileDTO getApplicantProfileById(long applicantId) {
		try {
			ApplicantProfile applicantProfile = applicantProfileRepository.findByApplicantId(applicantId);

			if (applicantProfile != null) {
				return convertEntityToDTO(applicantProfile);
			} else {

				throw new CustomException("Please Fill your  Profile", HttpStatus.NOT_FOUND);
			}
		} catch (CustomException e) {
			if (HttpStatus.NOT_FOUND.equals(e.getStatus())) {
				throw e;
			} else {

				throw new CustomException("Failed to get profile for applicant ID: " + applicantId,
						HttpStatus.INTERNAL_SERVER_ERROR);
			}
		}
	}

	// Converts a DTO to an applicant profile entity.
	private ApplicantProfile convertDTOToEntity(ApplicantProfileDTO applicantProfileDTO) {
		ApplicantProfile applicantProfile = new ApplicantProfile();
		applicantProfile.setBasicDetails(applicantProfileDTO.getBasicDetails());
		applicantProfile.setSkillsRequired(applicantProfileDTO.getSkillsRequired());
		applicantProfile.setRoles(applicantProfileDTO.getRoles());
		applicantProfile.setExperience(applicantProfileDTO.getExperience());
		applicantProfile.setQualification(applicantProfileDTO.getQualification());
		applicantProfile.setSpecialization(applicantProfileDTO.getSpecialization());
		applicantProfile.setPreferredJobLocations(applicantProfileDTO.getPreferredJobLocations());
		if (applicantProfileDTO.getRoles() == null) {
			applicantProfile.setRoles("ROLE_JOBAPPLICANT");
		} else {
			applicantProfile.setRoles(applicantProfileDTO.getRoles());
		}

		return applicantProfile;

	}

	// Converts an applicant profile entity to a DTO; returns null if entity is
	// null.
	public static ApplicantProfileDTO convertEntityToDTO(ApplicantProfile applicantProfile) {
		if (applicantProfile == null) {
			System.out.println("not exist");
			return null;
		}
		ApplicantProfileDTO applicantProfileDTO = new ApplicantProfileDTO();
		applicantProfileDTO.setBasicDetails(applicantProfile.getBasicDetails());
		applicantProfileDTO.setSkillsRequired(applicantProfile.getSkillsRequired());
		applicantProfileDTO.setRoles(applicantProfile.getRoles());
		return applicantProfileDTO;
	}

	// Updates the applicant's basic details and profile; throws CustomException if
	// applicant is not found.
	public String updateApplicantProfile(long applicantId, ApplicantProfileViewDTO updatedProfileDTO) {
		Applicant applicant = applicantService.getApplicantById(applicantId);
		if (applicant == null)
			throw new CustomException("Applicant not found " + applicantId, HttpStatus.NOT_FOUND);
		else {
			applicant.setName(updatedProfileDTO.getApplicant().getName());
			applicant.setMobilenumber(updatedProfileDTO.getApplicant().getMobilenumber());
			applicantService.save(applicant);
		}
		ApplicantProfile existingProfile = applicantProfileRepository.findByApplicantId(applicantId);
		if (existingProfile == null) {
			throw new CustomException("Your  profile not found and please fill profile " + applicantId,
					HttpStatus.NOT_FOUND);
		} else {
			existingProfile.setBasicDetails(updatedProfileDTO.getBasicDetails());
			existingProfile.setSkillsRequired(updatedProfileDTO.getSkillsRequired());
			existingProfile.setQualification(updatedProfileDTO.getQualification());
			existingProfile.setSpecialization(updatedProfileDTO.getSpecialization());
			applicantProfileRepository.save(existingProfile);
		}
		return "profile saved sucessfully";
	}

	
	public void deleteApplicantProfile(long applicantId) {
		try {
			applicantProfileRepository.deleteById((int) applicantId);
		} catch (Exception e) {
			throw new CustomException("Failed to delete profile for applicant ID: " + applicantId,
					HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}


	public int getApplicantProfileById1(int applicantId) {

		ApplicantProfile applicantProfile = applicantProfileRepository.findByApplicantId(applicantId);

		return applicantProfile != null ? applicantProfile.getProfileid() : 0;

	}


	@Transactional
	public void updateBasicDetails(Long applicantId, BasicDetailsDTO basicDetailsDTO) {
		ApplicantProfile applicantProfile = applicantProfileRepository.findByApplicantId(applicantId);

		applicantProfile.getBasicDetails().setFirstName(basicDetailsDTO.getFirstName());
		applicantProfile.getBasicDetails().setLastName(basicDetailsDTO.getLastName());
		applicantProfile.getBasicDetails().setDateOfBirth(basicDetailsDTO.getDateOfBirth());
		applicantProfile.getBasicDetails().setAddress(basicDetailsDTO.getAddress());
		applicantProfile.getBasicDetails().setCity(basicDetailsDTO.getCity());
		applicantProfile.getBasicDetails().setState(basicDetailsDTO.getState());
		applicantProfile.getBasicDetails().setPincode(basicDetailsDTO.getPincode());
		applicantProfile.getBasicDetails().setEmail(basicDetailsDTO.getEmail());
		applicantProfile.getBasicDetails().setAlternatePhoneNumber(basicDetailsDTO.getAlternatePhoneNumber());

		applicantProfileRepository.save(applicantProfile);
	}


	@Transactional
	public String updateApplicantProfile1(long applicantId, ApplicantProfileUpdateDTO updatedProfileDTO) {
		// Find applicant
		Applicant applicant = applicantService.getApplicantById(applicantId);

		// Find existing profile
		ApplicantProfile existingProfile = applicantProfileRepository.findByApplicantId(applicantId);
		if (existingProfile == null) {
			throw new CustomException("Your profile not found and please fill profile " + applicantId,
					HttpStatus.NOT_FOUND);
		} else {
			
			 // Extract existing skills from the database
	        Set<String> existingSkillNames = existingProfile.getSkillsRequired().stream()
	                .map(ApplicantSkills::getSkillName)
	                .collect(Collectors.toSet());

	        // Extract updated skills from the DTO
	        Set<String> updatedSkillNames = new HashSet<>();
	        if (updatedProfileDTO.getSkillsRequired() != null) {
	            for (ApplicantProfileUpdateDTO.SkillDTO skillDTO : updatedProfileDTO.getSkillsRequired()) {
	                updatedSkillNames.add(skillDTO.getSkillName());
	            }
	        }

	      
	        Set<String> removedSkills = new HashSet<>(existingSkillNames);
	        removedSkills.removeAll(updatedSkillNames);
	        
	
	        Set<String> addedSkills = new HashSet<>(updatedSkillNames);
	        addedSkills.removeAll(existingSkillNames);
	        
	        if(addedSkills != null) {
	        	for(String skillBadgeName: addedSkills) {
	        		try {
	        			SkillBadge skillBadge = skillBadgeRepository.findByName(skillBadgeName);
	        	    	applicantSkillBadgeRepository.updateFlagAsAdded(applicantId, skillBadge.getId());
	        	    }catch(Exception e) {
	        	    	System.out.println(e.getMessage());
	        	    }
	        	}
	        }
	        
	        if(removedSkills != null) {
	        for(String skillBadgeName: removedSkills ) {
	        	
	        	 
	        	    SkillBadge skillBadge = skillBadgeRepository.findByName(skillBadgeName);
	        	    System.out.println(skillBadge.getId()+"   "+skillBadge.getName());
	        	    try {
	        	    	applicantSkillBadgeRepository.updateFlagAsRemoved(applicantId, skillBadge.getId());
//	        	    applicantSkillBadgeRepository.deleteByApplicantIdAndSkillBadgeId(applicantId, skillBadge.getId());
	        	    }catch(Exception e) {
	        	    	System.out.println(e.getMessage());
	        	    }
	        }
	        }
			
			existingProfile.setExperience(updatedProfileDTO.getExperience());
			existingProfile.setQualification(updatedProfileDTO.getQualification());
			existingProfile.setSpecialization(updatedProfileDTO.getSpecialization());
			existingProfile.setPreferredJobLocations(new HashSet<>(updatedProfileDTO.getPreferredJobLocations()));

			 
			// Update skills required
			Set<ApplicantSkills> updatedSkills = new HashSet<>();
			if (updatedProfileDTO.getSkillsRequired() != null) {
				for (ApplicantProfileUpdateDTO.SkillDTO skillDTO : updatedProfileDTO.getSkillsRequired()) {
					ApplicantSkills skill = new ApplicantSkills();
					skill.setSkillName(skillDTO.getSkillName());
					skill.setExperience(skillDTO.getExperience());
					updatedSkills.add(skill);
				}
			}
			existingProfile.setSkillsRequired(updatedSkills);

			// Save the updated profile
			applicantProfileRepository.save(existingProfile);
		}

		return "Profile saved successfully";
	}

	public Applicant changeResumeSource(long applicantid) {
		Applicant applicant = applicantService.getApplicantById(applicantid);

		applicant.setLocalResume(false);
		return applicantService.save(applicant);

	}
	
	public ResponseEntity<?> getJobDetailsForApplicantSkillMatch(Long applicantId, Long jobId) {
	    System.out.println("Got job ID: " + jobId + " and applicant ID: " + applicantId);
 
	    if (jobId == null) {
	        System.out.println("Job ID is null");
	        return ResponseEntity.badRequest().body("Job ID cannot be null.");
	    }
 
	    final ModelMapper modelMapper = new ModelMapper();
	    Job job = jobRepository.findById(jobId).orElseThrow(() ->
	        new CustomException("Job with ID " + jobId + " not found.", HttpStatus.INTERNAL_SERVER_ERROR));
 
	    ApplicantProfile applicantProfile = applicantProfileRepository.findByApplicantId(applicantId);
	    if (applicantProfile == null) {
	        throw new CustomException("Applicant with ID " + applicantId + " not found.", HttpStatus.INTERNAL_SERVER_ERROR);
	    }
 
	    Set<ApplicantSkills> applicantSkills = applicantProfile.getSkillsRequired();
	    Set<RecuriterSkills> jobSkills = job.getSkillsRequired();
	    Set<ApplicantSkills> matchedSkills = new HashSet<>();
	    Set<ApplicantSkills> neitherMatchedNorNonMatchedSkills = new HashSet<>(applicantSkills);
	    int originalJobSkillsSize = jobSkills.size();
 
	    // Matching skills logic...
	    for (ApplicantSkills applicantSkill : applicantSkills) {
	        boolean isMatched = jobSkills.stream()
	            .anyMatch(jobSkill -> jobSkill.getSkillName().equalsIgnoreCase(applicantSkill.getSkillName()));
 
	        if (isMatched) {
	            matchedSkills.add(applicantSkill);
	            neitherMatchedNorNonMatchedSkills.remove(applicantSkill);
	        }
	    }
 
	    jobSkills.removeIf(jobSkill -> matchedSkills.stream()
	        .anyMatch(matchedSkill -> matchedSkill.getSkillName().equalsIgnoreCase(jobSkill.getSkillName())));
 
	    job.setSkillsRequired(jobSkills);
	    Double matchPercentage = ((double) matchedSkills.size() /originalJobSkillsSize) * 100;
	    System.out.println(matchPercentage + " match ");
	    int roundedMatchPercentage = (int) Math.round(matchPercentage);
	    System.out.println(roundedMatchPercentage + " round ");
	    JobDTO jobDTO = modelMapper.map(job, JobDTO.class);
	    jobDTO.setMatchPercentage(roundedMatchPercentage);
 
	    // Retrieve test scores for the specific applicant ID
	    Map<String, Double> testScores = applicantTestRepository.findTestScoresByApplicantId(applicantId);
	    Double aptitudeScore = testScores != null ? testScores.getOrDefault("aptitudeScore", 0.0) : 0.0;
	    Double technicalScore = testScores != null ? testScores.getOrDefault("technicalScore", 0.0) : 0.0;
	    jobDTO.setAptitudeScore(aptitudeScore);
	    jobDTO.setTechnicalScore(technicalScore);
	    System.out.println("Aptitude Score: " + aptitudeScore);
	    System.out.println("Technical Score: " + technicalScore);
	    jobDTO.setMatchedSkills(matchedSkills);
	    jobDTO.setAdditionalSkills(neitherMatchedNorNonMatchedSkills);
	    try {
	    List<ApplicantSkillBadge> applicantSkillsBadges = applicantSkillBadgeRepository.findPassedSkillBadgesByApplicantId(applicantId);
	    logger.info("got skill badge for applicantId",applicantSkillsBadges.size());
        if (applicantSkillsBadges != null && !applicantSkillsBadges.isEmpty()) {
            // Use the already retrieved applicantSkills to set the DTO
          jobDTO.setApplicantSkillBadges(applicantSkillsBadges);
        }
       
    } catch(Exception e) {
        e.printStackTrace();
    }
	    return ResponseEntity.ok(jobDTO);
	}
  

}
