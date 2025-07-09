package com.talentstream.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import com.talentstream.dto.CompanyProfileDTO;
import com.talentstream.entity.CompanyProfile;
import com.talentstream.entity.JobRecruiter;
import com.talentstream.exception.CustomException;
import com.talentstream.repository.CompanyProfileRepository;
import com.talentstream.repository.JobRecruiterRepository;
import java.util.Optional;

@Service
public class CompanyProfileService {

    private final CompanyProfileRepository companyProfileRepository;
    
    private static  final  Logger logger = LoggerFactory.getLogger(CompanyProfileService.class);

    @Autowired
    JobRecruiterRepository jobRecruiterRepository;

    // Initializes the CompanyProfileService with the specified repository.
    @Autowired
    public CompanyProfileService(CompanyProfileRepository companyProfileRepository) {
        this.companyProfileRepository = companyProfileRepository;
    }

    // Saves a new CompanyProfile for the specified job recruiter if it doesn't
    // already exist.
    public String saveCompanyProfile(CompanyProfileDTO companyProfileDTO, Long jobRecruiterId) throws Exception {
        JobRecruiter jobRecruiter = jobRecruiterRepository.findByRecruiterId(jobRecruiterId);
        if (jobRecruiter == null)
            throw new CustomException("Recruiter not found for ID: " + jobRecruiterId, HttpStatus.NOT_FOUND);
        else {
            if (!companyProfileRepository.existsByJobRecruiterId(jobRecruiterId)) {
                CompanyProfile companyProfile = convertDTOToEntity(companyProfileDTO);
                companyProfile.setJobRecruiter(jobRecruiter);
                companyProfile.setApprovalStatus("APPROVED");
                companyProfileRepository.save(companyProfile);
                return "profile saved sucessfully";
            } else {
                throw new CustomException("CompanyProfile was already updated.", HttpStatus.OK);
            }
        }

    }

    // Retrieves a CompanyProfile by its ID and converts it to a CompanyProfileDTO
    // if found.
    public Optional<CompanyProfileDTO> getCompanyProfileById(Long id) {
        Optional<CompanyProfile> companyProfile = companyProfileRepository.findById(id);
        return companyProfile.map(this::convertEntityToDTO);
    }

    public Optional<CompanyProfileDTO> getCompanyProfileDetailsByRecruiterId(Long jobRecruiterId){
    	Optional<CompanyProfile> companyProfile = companyProfileRepository.findAllByJobRecruiter_RecruiterId(jobRecruiterId);
    	if(jobRecruiterId==null) {
    		logger.info("recruiter not found for this id",jobRecruiterId);
    		return Optional.empty();
    	}
    	logger.info("sucessfully got company details",jobRecruiterId);
    	return companyProfile.map(this::convertEntityToDTO);
    	
    } 
    
    public String updateCompanyDetails(CompanyProfileDTO companyProfileDTO, Long jobRecruiterId) throws Exception {
    	JobRecruiter jobRecruiter = jobRecruiterRepository.findByRecruiterId(jobRecruiterId);
    	if(jobRecruiter == null) {
    		 throw new CustomException("Recruiter not found for ID: " + jobRecruiterId, HttpStatus.NOT_FOUND);
    	}
    	logger.info("Recruiter not found for ID: {}", jobRecruiterId);
    	
        CompanyProfile companyProfile = companyProfileRepository.findByJobRecruiter_RecruiterId(jobRecruiterId);
        if(companyProfile == null) {
        	 throw new CustomException("CompanyProfile not found.", HttpStatus.NOT_FOUND);
        }
        logger.info(" company profile found", jobRecruiterId);
    	    companyProfile.setCompanyName(companyProfileDTO.getCompanyName());
    	    if(!companyProfileDTO.getCompanyName().equals(jobRecruiter.getCompanyname())) {
    	    	jobRecruiter.setCompanyname(companyProfileDTO.getCompanyName());
    	    	jobRecruiterRepository.save(jobRecruiter);
    	    	logger.info("company details updated in job recruiter table",jobRecruiterId);
    	    	} 
           else
    	    {
    	    	logger.info("company name not updated in job recruiter table",jobRecruiterId);
    	    }
    	    companyProfile.setWebsite(companyProfileDTO.getWebsite());
    	    companyProfile.setPhoneNumber(companyProfileDTO.getPhoneNumber());
    	    companyProfile.setEmail(companyProfileDTO.getEmail());
    	    companyProfile.setHeadOffice(companyProfileDTO.getHeadOffice());
    	    companyProfile.setAboutCompany(companyProfileDTO.getAboutCompany());
    	    logger.info("about company updated sucessfully");
            companyProfile.setSocialProfiles(companyProfileDTO.getSocialProfiles());
            companyProfileRepository.save(companyProfile);
            logger.info("company details updated",jobRecruiterId);
            
            return "CompanyProfile updated sucessfully";
    	}

    // Converts a CompanyProfile entity to a CompanyProfileDTO.
    private CompanyProfileDTO convertEntityToDTO(CompanyProfile companyProfile) {
        CompanyProfileDTO dto = new CompanyProfileDTO();
        dto.setId(companyProfile.getId());
        dto.setCompanyName(companyProfile.getCompanyName());
        dto.setWebsite(companyProfile.getWebsite());
        dto.setPhoneNumber(companyProfile.getPhoneNumber());
        dto.setEmail(companyProfile.getEmail());
        dto.setHeadOffice(companyProfile.getHeadOffice());
        dto.setSocialProfiles(companyProfile.getSocialProfiles());
        dto.setAboutCompany(companyProfile.getAboutCompany()); 
        return dto;
    }

    // Converts a CompanyProfileDTO to a CompanyProfile entity.
    private CompanyProfile convertDTOToEntity(CompanyProfileDTO companyProfileDTO) {
        CompanyProfile entity = new CompanyProfile();

        entity.setId(companyProfileDTO.getId());
        entity.setCompanyName(companyProfileDTO.getCompanyName());
        entity.setWebsite(companyProfileDTO.getWebsite());
        entity.setPhoneNumber(companyProfileDTO.getPhoneNumber());
        entity.setEmail(companyProfileDTO.getEmail());
        entity.setHeadOffice(companyProfileDTO.getHeadOffice());
        entity.setSocialProfiles(companyProfileDTO.getSocialProfiles());
        entity.setAboutCompany(companyProfileDTO.getAboutCompany());
        return entity;
    }

    // Checks the approval status of a company profile based on the recruiter ID.
    public String checkApprovalStatus(Long jobRecruiterId) {
        CompanyProfile companyProfile = companyProfileRepository.findByJobRecruiter_RecruiterId(jobRecruiterId);

        if (companyProfile != null) {
            String approvalStatus = companyProfile.getApprovalStatus();

            switch (approvalStatus.toLowerCase()) {
                case "pending":
                    return "pending";
                case "approved":
                    return "approved";
                case "rejected":
                    return "rejected";
                default:
                    throw new CustomException("Invalid approval status.", HttpStatus.BAD_REQUEST);
            }
        } else {
            return "Profile not found";
        }
    }

    // Updates the approval status of a company profile based on the recruiter ID.
    public String updateApprovalStatus(Long jobRecruiterId, String newStatus) {
        CompanyProfile companyProfile = companyProfileRepository.findByJobRecruiter_RecruiterId(jobRecruiterId);

        if (companyProfile != null) {
            companyProfile.setApprovalStatus(newStatus);
            companyProfileRepository.save(companyProfile);

            return "Approval status updated successfully with: " + newStatus;
        } else {
            throw new CustomException("CompanyProfile not found for jobRecruiterId: " + jobRecruiterId,
                    HttpStatus.NOT_FOUND);
        }
    }

}