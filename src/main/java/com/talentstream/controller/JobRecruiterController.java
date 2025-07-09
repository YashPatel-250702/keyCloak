package com.talentstream.controller;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidKeyException;
import java.util.Base64;
import javax.validation.Valid;

import jakarta.persistence.EntityNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import com.talentstream.service.JwtUtil;
import com.talentstream.entity.Job;
import com.talentstream.service.MyUserDetailsService;
import com.talentstream.service.OtpService;
import com.talentstream.response.ResponseHandler;
import com.talentstream.dto.JobRecruiterDTO;
import com.talentstream.entity.AuthenticationResponse;
import com.talentstream.entity.JobRecruiter;
import com.talentstream.entity.PasswordRequest;
import com.talentstream.entity.RecruiterLogin;
import com.talentstream.entity.ResetPasswordRequest;
import com.talentstream.exception.CustomException;
import com.talentstream.repository.JobRecruiterRepository;
import com.talentstream.repository.RegisterRepository;
import com.talentstream.repository.JobRepository;
import com.talentstream.service.EmailService;
import com.talentstream.service.JobRecruiterService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@RestController
@CrossOrigin("*")
@RequestMapping("/recuriters")
public class JobRecruiterController {
    @Autowired
    private OtpService otpService;
    private Map<String, Boolean> otpVerificationMap = new HashMap<>();
    private static final Logger logger = LoggerFactory.getLogger(ApplicantProfileController.class);

    @Autowired
    private EmailService emailService;
    @Autowired
    JobRecruiterService recruiterService;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtUtil jwtTokenUtil;
    @Autowired
    MyUserDetailsService myUserDetailsService;
    @Autowired
    private JobRecruiterRepository recruiterRepository;

    @Autowired
    private JobRepository jobRepository;

    @Autowired
    RegisterRepository applicantRepository;

    @Autowired
    public JobRecruiterController(JobRecruiterService recruiterService) {
        this.recruiterService = recruiterService;
    }

    @PostMapping("/saverecruiters")
    public ResponseEntity<String> registerRecruiter(@Valid @RequestBody JobRecruiterDTO recruiterDTO,
            BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            // Handle validation errors
            Map<String, String> fieldErrors = new LinkedHashMap<>();

            bindingResult.getFieldErrors().forEach(fieldError -> {
                String fieldName = fieldError.getField();
                String errorMessage = fieldError.getDefaultMessage();

                // Append each field and its error message on a new line
                fieldErrors.merge(fieldName, errorMessage,
                        (existingMessage, newMessage) -> existingMessage + "\n" + newMessage);
            });

            // Construct the response body with each field and its error message on separate
            // lines
            StringBuilder responseBody = new StringBuilder();
            fieldErrors.forEach((fieldName, errorMessage) -> responseBody.append(fieldName).append(": ")
                    .append(errorMessage).append("\n"));

            return ResponseEntity.badRequest().body(responseBody.toString());
        }

        JobRecruiter recruiter = convertToEntity(recruiterDTO);
        try {
            logger.info("Registering recruiter with email: {}", recruiter.getEmail());
            return recruiterService.saveRecruiter(recruiterDTO);
        } catch (CustomException e) {
            logger.error("Error registering recruiter with email: {}", recruiter.getEmail(), e);
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            logger.error("Internal server error occurred while registering recruiter with email: {}",
                    recruiter.getEmail(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error registering applicant");
        }
    }
    
    public String decrypt(String encryptedPassword, String ivString) throws Exception {
        String secretKey = "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p"; // Must match the frontend key
        
        // Convert IV from Base64
        byte[] iv = Base64.getDecoder().decode(ivString);
        
        // Ensure the key length is correct
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "AES");

        // Use IV for decryption
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);

        byte[] decodedBytes = Base64.getDecoder().decode(encryptedPassword);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        
        return new String(decryptedBytes);
    }



    @PostMapping("/recruiterLogin")
    public ResponseEntity<Object> login(@RequestBody RecruiterLogin loginRequest) throws Exception {
    	
    	String decryptedPassword = decrypt(loginRequest.getPassword(), loginRequest.getIv()).trim();;
    	System.out.println("decryptedBytes "+decryptedPassword);
        JobRecruiter recruiter = recruiterService.login(loginRequest.getEmail(), decryptedPassword);
        loginRequest.setPassword(decryptedPassword);
        if (recruiter != null) {
            return createAuthenticationToken(loginRequest, recruiter);
        } else {
            boolean emailExists = recruiterService.emailExists(loginRequest.getEmail());

            if (emailExists) {
                logger.warn("Login failed for recruiter with email: {}. Incorrect password.", loginRequest.getEmail());

                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Incorrect password");
            } else {
                logger.warn("Login failed. No account found with email: {}", loginRequest.getEmail());
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("No account found with this email address");
            }
        }
    }

    @PostMapping("/registration-send-otp")
    public ResponseEntity<String> sendOtp(@RequestBody ResetPasswordRequest request) {
        String userEmail = request.getEmail();
        if (applicantRepository.existsByEmail(request.getEmail())) {
            return ResponseEntity.ok("Email already registered as applicant");
        }
        if (recruiterRepository.existsByEmail(request.getEmail())) {
            return ResponseEntity.ok("Email already registered recruiter");
        }
        if (applicantRepository.existsByMobilenumber(request.getMobilenumber())) {
            return ResponseEntity.ok("Mobile number already existed in applicant");
        }
        if (recruiterRepository.existsByMobilenumber(request.getMobilenumber())) {
            return ResponseEntity.ok("Mobile number already existed in recruiter");
        }

        JobRecruiter jobRecruiter = recruiterService.findByEmail(userEmail);
        if (jobRecruiter == null) {
            String otp = otpService.generateOtp(userEmail);
            emailService.sendOtpEmail(userEmail, otp);
            otpVerificationMap.put(userEmail, true);
            logger.info("OTP sent successfully to email: {}", userEmail);
            return ResponseEntity.ok("OTP sent to your email.");
        } else {
            logger.warn("Registration failed. Email {} is already registered.", userEmail);
            return ResponseEntity.badRequest().body("Email is already  registered.");
        }
    }

    private ResponseEntity<Object> createAuthenticationToken(RecruiterLogin login, JobRecruiter recruiter)
            throws Exception {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(login.getEmail(), login.getPassword()));
        } catch (BadCredentialsException e) {
            logger.warn("Login failed for recruiter with email: {}. Incorrect username or password.", login.getEmail());
            throw new Exception("Incorrect username or password", e);
        }
        final UserDetails userDetails = myUserDetailsService.loadUserByUsername(recruiter.getEmail());
        final String jwt = jwtTokenUtil.generateToken(userDetails);
        return ResponseHandler.generateResponse2("Login successfully" + userDetails.getAuthorities(), HttpStatus.OK,
                new AuthenticationResponse(jwt), recruiter.getEmail(), recruiter.getCompanyname(),
                recruiter.getRecruiterId(), recruiter.getMobilenumber());
    }

    @GetMapping("/viewRecruiters")
    public ResponseEntity<List<JobRecruiterDTO>> getAllJobRecruiters() {
        try {
            List<JobRecruiterDTO> jobRecruiters = recruiterService.getAllJobRecruiters();
            logger.info("Retrieved all job recruiters successfully");
            return ResponseHandler.generateResponse1("List of Job Recruiters", HttpStatus.OK, jobRecruiters);
        } catch (Exception e) {
            logger.error("Error retrieving job recruiters", e);
            return ResponseHandler.generateResponse1("Error retrieving job recruiters",
                    HttpStatus.INTERNAL_SERVER_ERROR, null);
        }
    }

    private JobRecruiter convertToEntity(JobRecruiterDTO recruiterDTO) {
        JobRecruiter recruiter = new JobRecruiter();
        recruiter.setCompanyname(recruiterDTO.getCompanyname());
        recruiter.setMobilenumber(recruiterDTO.getMobilenumber());
        recruiter.setEmail(recruiterDTO.getEmail());
        recruiter.setPassword(recruiterDTO.getPassword());
        recruiter.setRoles(recruiterDTO.getRoles());

        return recruiter;
    }

    @PostMapping("/authenticateRecruiter/{id}")
    public String authenticateRecruiter(@PathVariable Long id, @RequestBody PasswordRequest passwordRequest) {
        try {
            String secretKey = "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p";
            String decryptedOldPassword = decrypt(passwordRequest.getOldPassword(), passwordRequest.getIvOld(), secretKey);
            String decryptedNewPassword = decrypt(passwordRequest.getNewPassword(), passwordRequest.getIvNew(), secretKey);

            return recruiterService.authenticateRecruiter(id, decryptedOldPassword, decryptedNewPassword);
        } catch (Exception e) {
            e.printStackTrace();
            return "Password decryption failed";
        }
    }

    private String decrypt(String encryptedPassword, String iv, String secretKey) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(Base64.getDecoder().decode(iv));
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
        return new String(original);
    }

    @GetMapping("/appledjobs/{recruiterId}/unread-alert-count")
    public ResponseEntity<Integer> getUnreadAlertCount(@PathVariable long recruiterId) {
        try {
            JobRecruiter recruiter = recruiterRepository.findByRecruiterId(recruiterId);
            if (recruiter != null) {
                int unreadAlertCount = recruiter.getAlertCount();
                return ResponseEntity.ok(unreadAlertCount);
            } else {
                logger.warn("No recruiter found with ID: {}", recruiterId);
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
            }
        } catch (Exception e) {
            logger.error("Error getting unread alert count", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    @GetMapping("/job-alerts/{recruiterId}")
    public ResponseEntity<List<Job>> getAlerts(@PathVariable long recruiterId) {
        try {
            LocalDateTime minDateTime = LocalDateTime.now().minusDays(7); // Filter jobs from the last 7 days
            List<Job> notifications = jobRepository
                    .findJobsWithAlertCountAndRecentDateTimeGreaterThanAndRecruiterId(minDateTime, recruiterId);

            // Sort notifications based on recentApplicationDateTime in descending order
            Collections.sort(notifications, (job1, job2) -> {
                LocalDateTime dateTime1 = job1.getRecentApplicationDateTime();
                LocalDateTime dateTime2 = job2.getRecentApplicationDateTime();

                if (dateTime1 == null && dateTime2 == null) {
                    return 0;
                } else if (dateTime1 == null) {
                    return 1;
                } else if (dateTime2 == null) {
                    return -1;
                }

                // Compare in descending order
                return dateTime2.compareTo(dateTime1);
            });

            // Reset alert count for the recruiter
            JobRecruiter recruiter = recruiterRepository.findByRecruiterId(recruiterId);
            recruiter.setAlertCount(0);
            recruiterRepository.save(recruiter);
            logger.warn("No recruiter found with ID: {}", recruiterId);
            return ResponseEntity.ok(notifications);
        } catch (EntityNotFoundException e) {
            logger.warn("No recruiter found with ID: {}", recruiterId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        } catch (Exception e) {
            logger.error("Error getting job alerts", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }
}
