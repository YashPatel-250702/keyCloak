package com.talentstream.controller;

import java.util.HashMap;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.util.*;
import com.talentstream.dto.LoginDTO;

import java.util.Map;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import com.talentstream.dto.RegistrationDTO;
import com.talentstream.entity.Applicant;
import com.talentstream.entity.AuthenticationResponse;
import com.talentstream.entity.JobRecruiter;

import com.talentstream.entity.NewPasswordRequest;
import com.talentstream.entity.OtpVerificationRequest;
import com.talentstream.entity.PasswordRequest;
import com.talentstream.exception.CustomException;
import com.talentstream.repository.JobRecruiterRepository;
import com.talentstream.repository.RegisterRepository;
import com.talentstream.response.ResponseHandler;
import com.talentstream.service.EmailService;
import com.talentstream.service.JwtUtil;
import com.talentstream.service.MyUserDetailsService;
import com.talentstream.service.OtpService;
import com.talentstream.service.RegisterService;
import com.talentstream.service.JobRecruiterService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidKeyException;
import java.util.Base64;

@CrossOrigin("*")
@RestController
@RequestMapping("/applicant")
public class RegisterController {
	@Autowired
	MyUserDetailsService myUserDetailsService;

	@Autowired
	private OtpService otpService;
	@Autowired
	private RegisterRepository registerrepo;

	@Autowired
	private JobRecruiterRepository recruiterRepository;

	@Autowired
	private RegisterService registerService;

	@Autowired
	private RegisterRepository registerRepo;

	private Map<String, Boolean> otpVerificationMap = new HashMap<>();
	private static final Logger logger = LoggerFactory.getLogger(ApplicantProfileController.class);
	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	private JwtUtil jwtTokenUtil;

	@Autowired
	private EmailService emailService;

	@Autowired
	RegisterService regsiterService;
	@Autowired
	JobRecruiterService recruiterService;
	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	public RegisterController(RegisterService regsiterService) {
		this.regsiterService = regsiterService;

	}

	@PutMapping("/editApplicant/{applicantId}")
	public ResponseEntity<String> editApplicant(@PathVariable Long applicantId,
			@RequestBody RegistrationDTO updatedRegistrationDTO) {
		try {
			logger.info("Attempting to edit applicant with ID: {}", applicantId);
			ResponseEntity<String> response = registerService.editApplicant(applicantId, updatedRegistrationDTO);
			logger.info("Successfully edited applicant with ID: {}", applicantId);
			return response;
		} catch (Exception e) {
			logger.error("Error updating applicant with ID: {}", applicantId, e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error updating applicant");
		}
	}

	@PostMapping("/saveApplicant")
	public ResponseEntity<String> register(@Valid @RequestBody RegistrationDTO registrationDTO,
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
			logger.warn("Validation errors occurred during registering new applicant: {}", responseBody);
			return ResponseEntity.badRequest().body(responseBody.toString());
		}

		try {
			logger.info("Registering new applicant");
			return regsiterService.saveapplicant(registrationDTO);

		} catch (CustomException e) {
			logger.error("Custom exception while registering applicant: {}", e.getMessage(), e);
			return ResponseEntity.badRequest().body(e.getMessage());
		} catch (Exception e) {

			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error registering applicant");
		}
	}

	@PostMapping("/applicantLogin")
	public ResponseEntity<Object> login(@Valid @RequestBody LoginDTO loginDTO, BindingResult bindingResult)
			throws Exception {
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
			logger.warn("Validation errors occurred during registering new applicant: {}", responseBody);
			return ResponseEntity.badRequest().body(responseBody.toString());
		}

		try {
			Applicant applicant = null;
			logger.info("Attempting to login with email: {}", loginDTO.getEmail());

			if (regsiterService.isGoogleSignIn(loginDTO)) {
				// Handle Google Sign-In
				System.out.println("Before " + loginDTO.getEmail());
				logger.debug("Handling Google Sign-In for email: {}", loginDTO.getEmail());
				applicant = regsiterService.googleSignIn(loginDTO.getEmail(), loginDTO.getUtmSource());
				logger.debug("Google Sign-In successful for: {}", applicant.getEmail());
				System.out.println(applicant.getEmail());
				System.out.println("could return obj successfully");
			} else {
				// Handle regular login
				String secretKey = "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p";
				String decryptedOldPassword = decrypt(loginDTO.getPassword(), loginDTO.getIv(), secretKey);
				loginDTO.setPassword(decryptedOldPassword);
				applicant = regsiterService.login(loginDTO.getEmail(), decryptedOldPassword);

				if (applicant == null) {
					// Check if the email exists in the database
					boolean emailExists = regsiterService.emailExists(loginDTO.getEmail());
					if (emailExists) {
						// Incorrect password
						logger.warn("Incorrect password for email: {}", loginDTO.getEmail());
						return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Incorrect password");
					} else {
						// No account found with this email address
						logger.warn("No account found with email: {}", loginDTO.getEmail());
						return ResponseEntity.status(HttpStatus.NOT_FOUND)
								.body("No account found with this email address");
					}
				}
			}

			if (applicant != null) {
				return createAuthenticationToken(loginDTO, applicant);
			} else {
				logger.error("Login failed for email: {}", loginDTO.getEmail());
				return ResponseEntity.badRequest().body("Login failed");
			}
		} catch (BadCredentialsException e) {
			logger.error("Unauthorized access attempt for email: {}", loginDTO.getEmail(), e);
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Incorrect username or password");
		} catch (Exception e) {
			logger.error("Error during login for email: {}", loginDTO.getEmail(), e);
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error during login");
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

	private ResponseEntity<Object> createAuthenticationToken(LoginDTO loginDTO, Applicant applicant) throws Exception {
		try {
			if (regsiterService.isGoogleSignIn(loginDTO)) {
				// Handle Google sign-in separately
				System.out.println("Now I am at token gen");
				UserDetails userDetails = myUserDetailsService.loadUserByUsername(applicant.getEmail());
				final String jwt = jwtTokenUtil.generateToken(userDetails);
				return ResponseHandler.generateResponse("Login successfully" + userDetails.getAuthorities(),
						HttpStatus.OK, new AuthenticationResponse(jwt), applicant.getEmail(), applicant.getName(),
						applicant.getId(), applicant.getMobilenumber(), applicant.getUtmSource());
			} else {
				// Regular login functionality
				authenticationManager.authenticate(
						new UsernamePasswordAuthenticationToken(loginDTO.getEmail(), loginDTO.getPassword()));
				UserDetails userDetails = myUserDetailsService.loadUserByUsername(applicant.getEmail());
				final String jwt = jwtTokenUtil.generateToken(userDetails);
				return ResponseHandler.generateResponse("Login successfully" + userDetails.getAuthorities(),
						HttpStatus.OK, new AuthenticationResponse(jwt), applicant.getEmail(), applicant.getName(),
						applicant.getId(), applicant.getMobilenumber(), applicant.getUtmSource());
			}
		} catch (BadCredentialsException e) {
			throw new CustomException("Incorrect username or password", HttpStatus.UNAUTHORIZED);
		}

	}

	@PostMapping("/applicantsendotp")
	public ResponseEntity<String> sendOtp(@Valid @RequestBody Applicant request, BindingResult bindingResult) {
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
			logger.warn("Validation errors occurred during registering new applicant: {}", responseBody);
			return ResponseEntity.badRequest().body(responseBody.toString());
		}
		String userEmail = request.getEmail();
		String userMobile = request.getMobilenumber();
		logger.info("Attempting to send OTP to email: {} and mobile: {}", userEmail, userMobile);
		try {
			Applicant applicantByEmail = regsiterService.findByEmail(userEmail);
			Applicant applicantByMobile = regsiterService.findByMobilenumber(userMobile);
			JobRecruiter recruiterByEmail = findByEmail(userEmail);
			JobRecruiter recruiterByMobile = findByMobilenumber(userMobile);

			if (applicantByEmail == null && applicantByMobile == null && recruiterByEmail == null
					&& recruiterByMobile == null) {
				String otp = otpService.generateOtp(userEmail);
				emailService.sendOtpEmail(userEmail, otp);
				otpVerificationMap.put(userEmail, true);
				logger.info("OTP sent successfully to {}", userEmail);
				return ResponseEntity.ok("OTP sent to your email.");
			} else {
				if (applicantByEmail != null) {
					logger.warn("Email is already registered as an Applicant: {}", userEmail);
					throw new CustomException("Email is already registered as an Applicant.", null);
				} else if (recruiterByEmail != null) {
					logger.warn("Email is already registered as a Recruiter: {}", userEmail);
					throw new CustomException("Email is already registered as a Recruiter.", null);
				} else if (applicantByMobile != null) {
					logger.warn("Mobile number is already registered as an Applicant: {}", userMobile);
					throw new CustomException("Mobile number is already registered as an Applicant.", null);
				} else if (recruiterByMobile != null) {
					logger.warn("Mobile number is already registered as a Recruiter: {}", userMobile);
					throw new CustomException("Mobile number is already registered as a Recruiter.", null);
				} else {
					throw new CustomException("Email or mobile number is already registered.", null);
				}
			}
		} catch (CustomException e) {
			logger.error("Custom exception occurred: {}", e.getMessage());
			return ResponseEntity.badRequest().body(e.getMessage());
		} catch (Exception e) {
			logger.error("Error sending OTP to email: {}", userEmail, e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error sending OTP");
		}
	}

	@PostMapping("/forgotpasswordsendotp")
	public ResponseEntity<String> ForgotsendOtp(@Valid @RequestBody Applicant request, BindingResult bindingResult) {

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
			logger.warn("Validation errors occurred during registering new applicant: {}", responseBody);
			return ResponseEntity.badRequest().body(responseBody.toString());
		}
		String userEmail = request.getEmail();
		logger.info("Sending OTP for password recovery to email: {}", userEmail);
		Applicant applicant = regsiterService.findByEmail(userEmail);
		if (applicant != null) {
			String otp = otpService.generateOtp(userEmail);
			emailService.sendOtpEmail(userEmail, otp);
			otpVerificationMap.put(userEmail, true);
			logger.info("OTP sent successfully to email: {}", userEmail);
			return ResponseEntity.ok("OTP sent successfully");
		} else {
			logger.warn("Email not found: {}", userEmail);
			return ResponseEntity.badRequest().body("Email not found.");
		}
	}

	@PostMapping("/applicantverify-otp")
	public ResponseEntity<String> verifyOtp(@Valid @RequestBody OtpVerificationRequest verificationRequest,
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
			logger.warn("Validation errors occurred during registering new applicant: {}", responseBody);
			return ResponseEntity.badRequest().body(responseBody.toString());
		}
		try {
			String otp = verificationRequest.getOtp();
			String email = verificationRequest.getEmail();

			if (otpService.validateOtp(email, otp)) {
				logger.info("OTP verified successfully for email: {}", email);
				return ResponseEntity.ok("OTP verified successfully");
			} else {
				logger.warn("Incorrect OTP or Timeout for email: {}", email);
				throw new CustomException("Incorrect OTP or Timeout.", HttpStatus.BAD_REQUEST);
			}
		} catch (CustomException e) {
			logger.error("OTP verification failed: {}", e.getMessage());
			return ResponseEntity.status(e.getStatus()).body(e.getMessage());
		} catch (Exception e) {
			logger.error("Error verifying OTP for email: {}", e);
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error verifying OTP");
		}
	}

	@PostMapping("/applicantreset-password/{email}")
	public ResponseEntity<String> setNewPassword(@Valid @RequestBody NewPasswordRequest request,
			BindingResult bindingResult, @PathVariable String email) {
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
			logger.warn("Validation errors occurred during registering new applicant: {}", responseBody);
			return ResponseEntity.badRequest().body(responseBody.toString());
		}

		try {
			logger.info("Request to reset password for email: {}", email);

			String newpassword = request.getPassword();
			String confirmedPassword = request.getConfirmedPassword();

			if (email == null) {
				throw new CustomException("Email not found or is invalid.", HttpStatus.BAD_REQUEST);
			}

			Applicant applicant = regsiterService.findByEmail(email);
			if (applicant == null) {
				logger.error("No user found with email: {}", email);
				throw new CustomException("User not found.", HttpStatus.BAD_REQUEST);
			}

			applicant.setPassword(passwordEncoder.encode(newpassword));
			regsiterService.addApplicant(applicant);
			logger.info("Password reset successfully for email: {}", email);
			return ResponseEntity.ok("Password reset was done successfully");
		} catch (CustomException e) {
			logger.error("CustomException during password reset for email: {}: {}", email, e.getMessage());
			return ResponseEntity.status(e.getStatus()).body(e.getMessage());
		} catch (Exception e) {
			logger.error("Error resetting password for email: {}", email, e);
			System.out.println(e.getMessage());
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error resetting password");
		}
	}

	@GetMapping("/viewApplicants")

	public ResponseEntity<List<Applicant>> getAllApplicants() {
		logger.info("Fetching all applicants");

		try {
			List<Applicant> applicants = regsiterService.getAllApplicants();
			return ResponseEntity.ok(applicants);
		} catch (Exception e) {
			logger.error("Failed to retrieve applicants", e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
		}

	}

	@PostMapping("/applicantsignOut")
	public ResponseEntity<Void> signOut(@AuthenticationPrincipal Applicant user) {
		logger.info("Signing out user: {}", user.getEmail());
		try {
			SecurityContextHolder.clearContext();
			return ResponseEntity.noContent().build();
		} catch (Exception e) {
			logger.error("Error during sign out for user: {}", user.getEmail(), e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
		}
	}

	public void setOtpService(OtpService otpService2) {
		otpService = otpService2;
		logger.debug("OTP Service set successfully");

	}

	@PostMapping("/authenticateUsers/{id}")
	public ResponseEntity<String> authenticateUser(@RequestBody PasswordRequest passwordRequest,
			@PathVariable long id) {
		String secretKey = "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p";
		String decryptedOldPassword = null;
		String decryptedNewPassword = null;
		try {
			decryptedOldPassword = decrypt1(passwordRequest.getOldPassword(), passwordRequest.getIvOld(), secretKey);
			decryptedNewPassword = decrypt1(passwordRequest.getNewPassword(), passwordRequest.getIvNew(), secretKey);
		} catch (Exception e) {
	        e.printStackTrace();
	        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Password decryption failed");
	    }

	    ResponseEntity<String> result = regsiterService.authenticateUser(id, decryptedOldPassword, decryptedNewPassword);
	    return result;
	}

	private String decrypt1(String encryptedPassword, String iv, String secretKey) throws Exception {
		IvParameterSpec ivSpec = new IvParameterSpec(Base64.getDecoder().decode(iv));
		SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "AES");

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

		byte[] original = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
		return new String(original);
	}

	public JobRecruiter findByEmail(String userEmail) {
		try {
			System.out.println(userEmail);

			return recruiterRepository.findByEmail(userEmail);

		} catch (Exception e) {

			throw new CustomException("Error finding applicant by email", HttpStatus.INTERNAL_SERVER_ERROR);
		}

	}

	public JobRecruiter findByMobilenumber(String userMobile) {
		try {

			return recruiterRepository.findByMobilenumber(userMobile);

		} catch (Exception e) {

			throw new CustomException("Error finding applicant by Mobile Number", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	@GetMapping("/getApplicantById/{id}")
	public ResponseEntity<Applicant> getApplicantById(@PathVariable long id) {
		Applicant applicant = registerRepo.findById(id);
		return ResponseEntity.ok(applicant);
	}

	@GetMapping("/getResumeId/{id}")
	public ResponseEntity<String> getResumeIdByApplicantId(@PathVariable long id) {
		Applicant applicant = registerRepo.findById(id);
		if (applicant == null) {
			return ResponseEntity.notFound().build();
		}
		String resumeId = applicant.getResumeId();
		return ResponseEntity.ok(resumeId);
	}

	@PutMapping("/closeAccount/{id}")
    public ResponseEntity<String> closeAccount(@PathVariable Long id) {
 
        try {
        	registerService.closeAccount(id);
            return ResponseEntity.ok("Applicant account closed successfully");
        } catch (CustomException e) {
            return ResponseEntity.status(e.getStatus()).body(e.getMessage());
        }
        catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

}
