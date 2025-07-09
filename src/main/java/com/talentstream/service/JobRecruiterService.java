package com.talentstream.service;

import java.util.List;
import java.util.stream.Collectors;

import javax.persistence.EntityNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.talentstream.exception.CustomException;
import com.talentstream.dto.JobRecruiterDTO;
import com.talentstream.entity.JobRecruiter;
import com.talentstream.repository.JobRecruiterRepository;
import com.talentstream.repository.RegisterRepository;

@Service
public class JobRecruiterService {
	
	    private PasswordEncoder passwordEncoder;	    
	   @Autowired
        JobRecruiterRepository recruiterRepository;
	   @Autowired
	   RegisterRepository applicantRepository;
 
	   public JobRecruiterService(JobRecruiterRepository recruiterRepository, PasswordEncoder passwordEncoder) {
	        this.recruiterRepository = recruiterRepository;
	        this.passwordEncoder = passwordEncoder;
	    }
 
	   public ResponseEntity<String> saveRecruiter(JobRecruiterDTO recruiterDTO) {
	    	JobRecruiter recruiter=convertToEntity(recruiterDTO);
	    	try {
	           
	            if (recruiterRepository.existsByEmail(recruiter.getEmail()) || applicantRepository.existsByEmail(recruiter.getEmail())) {
	                throw new CustomException("Failed to register/Email already exists", HttpStatus.BAD_REQUEST);
	            }
	            if(recruiterRepository.existsByMobilenumber(recruiter.getMobilenumber())||applicantRepository.existsByMobilenumber(recruiter.getMobilenumber()))
	            {
	            	throw new CustomException("Mobile number already existed ,enter new mobile number",null);
	            }
	            System.out.println("befor edncoind pwd");
	            recruiter.setPassword(passwordEncoder.encode(recruiter.getPassword()));
	            System.out.println("after edncoind pwd ");
	            recruiterRepository.save(recruiter);
	            System.out.println("after edncoind pwd and saving");
	            return ResponseEntity.ok("Recruiter registered successfully");
	        } catch (CustomException e) {
	            throw e;
	        } catch (Exception e) {
	            throw new CustomException("Error registering recruiter", HttpStatus.INTERNAL_SERVER_ERROR);
	        }
	    }
	   private JobRecruiter convertToEntity(JobRecruiterDTO recruiterDTO) {
	        JobRecruiter recruiter = new JobRecruiter();
//	        recruiter.setRecruiterId(recruiterDTO.getRecruiterId());
	        recruiter.setCompanyname(recruiterDTO.getCompanyname());
	        recruiter.setMobilenumber(recruiterDTO.getMobilenumber());
	        recruiter.setEmail(recruiterDTO.getEmail());
	        recruiter.setPassword(recruiterDTO.getPassword());
	        recruiter.setRoles(recruiterDTO.getRoles());        
	
	        return recruiter;
	    }
    public JobRecruiter login(String email, String password) {
    	JobRecruiter recruiter = recruiterRepository.findByEmail(email);
        if (recruiter != null && passwordEncoder.matches(password, recruiter.getPassword())) {
            return recruiter;
        } else {
        	
       	 return null;
        }
   }
  
   public boolean emailExists(String email) {
       return recruiterRepository.existsByEmail(email);
   }
    
    public JobRecruiter findById(Long id) {
    	return recruiterRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("JobRecruiter not found for ID: " + id));
        
    }
    public List<JobRecruiterDTO> getAllJobRecruiters() {
        try {
            List<JobRecruiter> jobRecruiters = recruiterRepository.findAll();
            return jobRecruiters.stream()
                    .map(this::convertToDTO)
                    .collect(Collectors.toList());
        } catch (Exception e) {
            throw new CustomException("Error retrieving job recruiters", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    
    public void updatePassword(String userEmail, String newPassword) {
        JobRecruiter jobRecruiter = recruiterRepository.findByEmail(userEmail);
        if (jobRecruiter != null) {
            jobRecruiter.setPassword(newPassword);
            recruiterRepository.save(jobRecruiter);
        } else {
            throw new EntityNotFoundException("JobRecruiter not found for email: " + userEmail);
        }
    }
 
	public JobRecruiter findByEmail(String userEmail) {
			return recruiterRepository.findByEmail(userEmail);
	}
 
	public void addRecruiter(JobRecruiter jobRecruiter) {
		recruiterRepository.save(jobRecruiter);
			}
	
	
	private JobRecruiterDTO convertToDTO(JobRecruiter recruiter) {
        JobRecruiterDTO recruiterDTO = new JobRecruiterDTO();
        //recruiterDTO.setRecruiterId(recruiter.getRecruiterId());
        recruiterDTO.setCompanyname(recruiter.getCompanyname());
        recruiterDTO.setMobilenumber(recruiter.getMobilenumber());
        recruiterDTO.setEmail(recruiter.getEmail());
        recruiterDTO.setPassword(recruiter.getPassword());
        recruiterDTO.setRoles(recruiter.getRoles());
 
        return recruiterDTO;
    }
	
	public String authenticateRecruiter(Long id,String oldPassword, String newPassword) {
	   
	        try {
	        	JobRecruiter opUser = recruiterRepository.findByRecruiterId(id);
	            System.out.println(opUser.getPassword());
	            System.out.println(passwordEncoder.encode(oldPassword));
	            if (opUser != null) {
	            	if(passwordEncoder.matches(oldPassword, opUser.getPassword())) {
	            		if (passwordEncoder.matches(newPassword, opUser.getPassword())) {
	            			return "your new password should not be same as old password";
	            		}
	            		opUser.setPassword(passwordEncoder.encode(newPassword));
	            		recruiterRepository.save(opUser);

	                    return "Password updated and stored";
	            	}
	            	else {
	            		return "Your old password not matching with data base password";
	            	}
	            	            }
	            else {
	            	return "User not found with given id";
	            }
	        }
	               
	    	catch (Exception e) {
	         	            e.printStackTrace();	            
	           return "user not found with this given id";
	        }
			
	    }
	}

 

	
