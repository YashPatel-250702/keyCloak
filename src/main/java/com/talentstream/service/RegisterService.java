package com.talentstream.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Random;

import com.talentstream.exception.CustomException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.talentstream.entity.Applicant;
import com.talentstream.repository.JobRecruiterRepository;
import com.talentstream.repository.RegisterRepository;
import com.talentstream.dto.LoginDTO;
import com.talentstream.dto.RegistrationDTO;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestTemplate;
import com.talentstream.dto.ResumeRegisterDto;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.util.UUID;

@Service
public class RegisterService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JobRecruiterRepository recruiterRepository;

    @Autowired
    RegisterRepository applicantRepository;

    @Autowired
    private RestTemplate restTemplate;

    public RegisterService(RegisterRepository applicantRepository) {
        this.applicantRepository = applicantRepository;
    }

    public Applicant login(String email, String password) {
        System.out.println("Login is Mached " + email);
        try {
            Applicant applicant = applicantRepository.findByEmail(email);
            if (applicant != null && passwordEncoder.matches(password, applicant.getPassword())) {
                applicant.setUtmSource("Not first time");
                return applicant;
            } else {
                return null;
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    public boolean isGoogleSignIn(LoginDTO loginDTO) {
        // Check if password is null or empty
        return loginDTO.getPassword() == null || loginDTO.getPassword().isEmpty();
    }

   
    public Applicant googleSignIn(String email, String utmSource) {
        Applicant applicant = null;

        try {
            applicant = applicantRepository.findByEmail(email);

            if (applicant == null) {
                // If the applicant does not exist, create a new one
                Applicant newApplicant = new Applicant();
                newApplicant.setEmail(email);
                newApplicant.setUtmSource(utmSource);
                // newApplicant.setAppicantStatus("Active");
                // Generate a random number as the password
                String randomPassword = generateRandomPassword();
                newApplicant.setPassword(passwordEncoder.encode(randomPassword));

                LocalDateTime now = LocalDateTime.now();
                newApplicant.setCreatedAt(now);

                // Save the new applicant
                Applicant applicant1 = applicantRepository.save(newApplicant);
                applicant1.setUtmSource("first time");
                System.out.println("User resume ID: ");
                ResumeRegisterDto resume = new ResumeRegisterDto();
                // String[] nameParts = applicant1.getName().toLowerCase().split("\\s+");

                String firstName = UUID.randomUUID().toString().replaceAll("[^a-z0-9._-]", "").substring(0, 10);
                resume.setName(firstName);
                String randomString = UUID.randomUUID().toString().replaceAll("[^a-z0-9._-]", "").substring(0, 10);
                String username = firstName + randomString;
                resume.setUsername(username);
                resume.setEmail(applicant1.getEmail().toLowerCase());
                resume.setPassword(applicant1.getPassword());
                resume.setLocale("en-US");
               
                applicant1.setResumeId(String.valueOf(applicant1.getId()));
                applicantRepository.save(applicant1);
                System.out.println("Applicant updated");

              

                return applicant1;
            } else {
                applicant.setUtmSource("not first time");
                return applicant;
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        System.out.println("Checking");
        System.out.println("Able to return applicant");
        System.out.println(applicant != null ? applicant.getEmail() : "Applicant is null");
        return applicant;
    }

    private String generateRandomPassword() {
        // Generate a random 6-digit password
        Random random = new Random();
        int randomPassword = 100000 + random.nextInt(900000);
        return String.valueOf(randomPassword);
    }

   

    public Applicant findById(Long id) {
        try {
            return applicantRepository.findById(id);
        } catch (EntityNotFoundException e) {
            throw e;
        } catch (Exception e) {
            throw new CustomException("Error finding applicant by ID", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public Applicant findByEmail(String userEmail) {
        try {
            System.out.println(userEmail);
            return applicantRepository.findByEmail(userEmail);

        } catch (Exception e) {

            throw new CustomException("Error finding applicant by email", HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    public Applicant findByMobilenumber(String userMobile) {
        try {

            return applicantRepository.findByMobilenumber(userMobile);

        } catch (Exception e) {

            throw new CustomException("Error finding applicant by Mobile Number", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public List<Applicant> getAllApplicants() {
        try {
            return applicantRepository.findAll();
        } catch (Exception e) {
            throw new CustomException("Error retrieving applicants", HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    public void updatePassword(String userEmail, String newPassword) {
        try {
            Applicant applicant = applicantRepository.findByEmail(userEmail);
            if (applicant != null) {
                applicant.setPassword(passwordEncoder.encode(newPassword));
                applicantRepository.save(applicant);
            } else {
                throw new EntityNotFoundException("Applicant not found for email: " + userEmail);
            }
        } catch (EntityNotFoundException e) {
            throw e;
        } catch (Exception e) {
            throw new CustomException("Error updating password", HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    public ResponseEntity<String> saveapplicant(RegistrationDTO registrationDTO) {
        try {

            Applicant applicant = mapRegistrationDTOToApplicant(registrationDTO);
            if (applicantRepository.existsByEmail(applicant.getEmail())
                    || recruiterRepository.existsByEmail(applicant.getEmail())) {
                throw new CustomException("Email already registered", null);
            }
            if (applicantRepository.existsByMobilenumber(applicant.getMobilenumber())
                    || recruiterRepository.existsByMobilenumber(applicant.getMobilenumber())) {
                throw new CustomException("Mobile number already existed", null);
            }

            applicant.setPassword(passwordEncoder.encode(applicant.getPassword()));
            Applicant applicant1 = applicantRepository.save(applicant);
            ResumeRegisterDto resume = new ResumeRegisterDto();
            String[] nameParts = applicant1.getName().toLowerCase().split("\\s+");
            String firstName = nameParts[0];
            resume.setName(firstName);
            String randomString = UUID.randomUUID().toString().replaceAll("[^a-z0-9._-]", "").substring(0, 10);
            String username = firstName + randomString;
            resume.setUsername(username);
            resume.setEmail(applicant1.getEmail().toLowerCase());
            resume.setPassword(applicant1.getPassword());
            resume.setLocale("en-US");
          
            applicant1.setResumeId(String.valueOf(applicant1.getId()));
            applicantRepository.save(applicant1);
            System.out.println("Applicant updated");

            
            return ResponseEntity.ok("Applicant registered successfully");
        } catch (CustomException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error registering applicant");
        }
    }

    // Check if the email exists in the database
    public boolean emailExists(String email) {
        return applicantRepository.existsByEmail(email);
    }

    public void addApplicant(Applicant applicant) {
        try {
            Applicant applicant1 = applicantRepository.save(applicant);
            //requestPasswordReset(applicant1);

        } catch (Exception e) {
            System.out.println(e.getMessage());
            throw new CustomException("Error adding applicant", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private Applicant mapRegistrationDTOToApplicant(RegistrationDTO registrationDTO) {
        Applicant applicant = new Applicant();
        applicant.setName(registrationDTO.getName());
        applicant.setEmail(registrationDTO.getEmail());
        applicant.setMobilenumber(registrationDTO.getMobilenumber());
        applicant.setPassword(registrationDTO.getPassword());
        applicant.setUtmSource(registrationDTO.getUtmSource());
        LocalDateTime now = LocalDateTime.now();
        applicant.setCreatedAt(now);
        return applicant;
    }

   
    public ResponseEntity<String> authenticateUser(long id, String oldPassword, String newPassword) {
    	 
		try {
			Applicant opUser = applicantRepository.findById(id);
			if (opUser == null) {
 
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found with given id");
			}
 
			if (!passwordEncoder.matches(oldPassword, opUser.getPassword())) {
 
				return ResponseEntity.status(HttpStatus.BAD_REQUEST)
						.body("Your old password not matching with data base password");
			}
 
			if (passwordEncoder.matches(newPassword, opUser.getPassword())) {
				return ResponseEntity.status(HttpStatus.BAD_REQUEST)
						.body("your new password should not be same as old password");
			}
 
			opUser.setPassword(passwordEncoder.encode(newPassword));
			Applicant savedUser = applicantRepository.save(opUser);
 
			return ResponseEntity.status(HttpStatus.OK).body("Password updated and stored");
 
		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("Error occurred while updating password");
 
		}
	}

    public String requestPasswordReset(Applicant opUser) {
        // Prepare headers
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        // Set up the payload
        JsonObject payload = new JsonObject();
        payload.addProperty("email", opUser.getEmail());

        // Create HttpEntity with headers and payload
        HttpEntity<String> requestEntity = new HttpEntity<>(payload.toString(), headers);

        // Define the endpoint URL
        String forgotPasswordUrl = "https://resume.bitlabs.in:5173//api/auth/forgot-password";

        try {
            // Make the POST request
            ResponseEntity<String> response = restTemplate.postForEntity(forgotPasswordUrl, requestEntity,
                    String.class);

            // Parse the JSON response
            Gson gson = new Gson();
            JsonObject jsonResponse = gson.fromJson(response.getBody(), JsonObject.class);

            // Access the resetToken
            String resetToken = jsonResponse.get("resetToken").getAsString();

            // Print the resetToken
            System.out.println("Reset Token: " + resetToken);

            // Step 2: Reset Password
            JsonObject payloadForPasswordReset = new JsonObject();
            payloadForPasswordReset.addProperty("token", resetToken);
            payloadForPasswordReset.addProperty("password", opUser.getPassword());

            HttpEntity<String> passwordResetRequestEntity = new HttpEntity<>(payloadForPasswordReset.toString(),
                    headers);
            String resetPasswordUrl = "https://resume.bitlabs.in:5173/api/auth/reset-password";

            ResponseEntity<String> passwordResetResponse = restTemplate.postForEntity(resetPasswordUrl,
                    passwordResetRequestEntity, String.class);

            System.out.println("Password Reset Response: " + passwordResetResponse.getBody());

            // Return the resetToken for further processing
            return resetToken;

        } catch (Exception e) {
            // Log and handle the exception
            e.printStackTrace();
            return "Failed to request password reset.";
        }
    }

    public ResponseEntity<String> editApplicant(Long applicantId, RegistrationDTO updatedRegistrationDTO) {
        try {

            Applicant existingApplicant = applicantRepository.findById(applicantId);

            if (existingApplicant != null) {

                if (updatedRegistrationDTO.getName() != null) {
                    existingApplicant.setName(updatedRegistrationDTO.getName());
                }

                if (updatedRegistrationDTO.getMobilenumber() != null) {
                    existingApplicant.setMobilenumber(updatedRegistrationDTO.getMobilenumber());
                }

                if (updatedRegistrationDTO.getEmail() != null) {
                    existingApplicant.setMobilenumber(updatedRegistrationDTO.getEmail());
                }

                if (updatedRegistrationDTO.getPassword() != null) {
                    existingApplicant.setPassword(passwordEncoder.encode(updatedRegistrationDTO.getPassword()));
                }

                applicantRepository.save(existingApplicant);

                return ResponseEntity.ok("Applicant updated successfully");
            } else {
                return ResponseEntity.badRequest().body("Applicant not found with id: " + applicantId);
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error updating applicant");
        }
    }

    public void closeAccount(Long id) {
 
		Applicant applicant = applicantRepository.findById(id);
 
		if (applicant == null) {
			throw new CustomException("Applicant not found", HttpStatus.NOT_FOUND);
		}
 
		String email = applicant.getEmail();
		String mobile = applicant.getMobilenumber();
 
		boolean isEmailDeleted = email.endsWith("_deleted");
		boolean isMobileDeleted = mobile != null && mobile.startsWith("0");
 
		// If already deleted (email and mobile), throw error
		if (isEmailDeleted && (mobile == null || isMobileDeleted)) {
			throw new CustomException("Account already deleted", HttpStatus.BAD_REQUEST);
		}
 
		// Update email
		if (!isEmailDeleted) {
			applicant.setEmail(email + "_deleted");
		}
 
		// Update mobile only if it's not already starting with "0"
		if (mobile == null || !mobile.startsWith("0")) {
			applicant.setMobilenumber(mobile == null ? "0" : "0" + mobile);
		}
 
		applicantRepository.save(applicant);
	}
 

}
