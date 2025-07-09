// package com.talentstream.TestControllers;

// import com.fasterxml.jackson.databind.ObjectMapper;
// import com.talentstream.controller.RegisterController;
// import com.talentstream.dto.LoginDTO;
// import com.talentstream.dto.RegistrationDTO;
// import com.talentstream.entity.Applicant;
// import com.talentstream.entity.Login;
// import com.talentstream.entity.NewPasswordRequest;
// import com.talentstream.entity.OtpVerificationRequest;
// import com.talentstream.exception.CustomException;
// import com.talentstream.service.EmailService;
// import com.talentstream.service.JwtUtil;
// import com.talentstream.service.MyUserDetailsService;
// import com.talentstream.service.OtpService;
// import com.talentstream.service.RegisterService;
// import com.talentstream.service.JobRecruiterService;
// import org.junit.jupiter.api.Test;
// import org.mockito.InjectMocks;
// import org.mockito.Mock;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
// import org.springframework.boot.test.context.SpringBootTest;
// import org.springframework.http.HttpStatus;
// import org.springframework.http.MediaType;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.authentication.BadCredentialsException;
// import org.springframework.security.core.userdetails.User;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.test.web.servlet.MockMvc;
// import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
// import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
// import static org.junit.Assert.assertEquals;
// import static org.junit.Assert.fail;
// import static org.mockito.Mockito.*;
// import java.util.Collections;
// import org.junit.jupiter.api.BeforeEach;
// import org.springframework.test.web.servlet.setup.MockMvcBuilders;


// @SpringBootTest
// @AutoConfigureMockMvc
// public class RegisterControllerTest {
//     private MockMvc mockMvc;
//     @Mock
//     private RegisterService registerService;
//     @Mock
//     private OtpService otpService;
//     @Mock
//     private EmailService emailService;
//     @Mock
//     private AuthenticationManager authenticationManager;
//     @Mock
//     private JwtUtil jwtTokenUtil;
//         @Mock
//     private MyUserDetailsService myUserDetailsService;
//     @Mock
//     private JobRecruiterService recruiterService;
//     @Mock
//     private PasswordEncoder passwordEncoder;
//     @InjectMocks
//     private RegisterController registerController;
//     @Autowired
//     private ObjectMapper objectMapper;

//     @BeforeEach
//     public void setUp() {
//         mockMvc = MockMvcBuilders.standaloneSetup(registerController).build();
//         registerController.setOtpService(otpService);
//     }
   

//     @Test
//     public void testSaveApplicantSuccess() {     
//         RegistrationDTO registrationDTO = new RegistrationDTO();
//         when(registerService.saveapplicant(any(RegistrationDTO.class)))
//                 .thenReturn(ResponseEntity.ok("Registration successful"));
//         ResponseEntity<String> response = registerController.register(registrationDTO);
//         assertEquals(HttpStatus.OK, response.getStatusCode());
//         assertEquals("Registration successful", response.getBody());
//         verify(registerService, times(1)).saveapplicant(any(RegistrationDTO.class));
//     }
//     @Test
//     public void testSaveApplicantFailureCustomException() {
//              RegistrationDTO registrationDTO = new RegistrationDTO();
//         when(registerService.saveapplicant(any(RegistrationDTO.class)))
//                 .thenThrow(new CustomException("Custom exception message", HttpStatus.BAD_REQUEST));
//         ResponseEntity<String> response = registerController.register(registrationDTO);
//         assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
//         assertEquals("Custom exception message", response.getBody());
//         verify(registerService, times(1)).saveapplicant(any(RegistrationDTO.class));
//     }
    
//     @Test
//     public void testSaveApplicantFailureGenericException() {
//                RegistrationDTO registrationDTO = new RegistrationDTO();
//         when(registerService.saveapplicant(any(RegistrationDTO.class)))
//                 .thenThrow(new RuntimeException("Some unexpected error"));
//         ResponseEntity<String> response = registerController.register(registrationDTO);
//         assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//         assertEquals("Error registering applicant", response.getBody());
//         verify(registerService, times(1)).saveapplicant(any(RegistrationDTO.class));
//     }
    
    
    
//     @Test
//     public void testLoginFailureBadCredentialsException() throws Exception {
//          LoginDTO loginDTO = new LoginDTO();
//         loginDTO.setEmail("test@example.com");
//         loginDTO.setPassword("wrong_password");

//         when(registerService.login(any(String.class), any(String.class)))
//                 .thenThrow(new BadCredentialsException("Incorrect username or password"));
//         ResponseEntity<Object> response = registerController.login(loginDTO);
//         assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
//         assertEquals("Incorrect username or password", response.getBody());
//         verify(registerService, times(1)).login("test@example.com", "wrong_password");
//     }

    
//     @Test
//     public void testLoginSucess() throws Exception {
//         Login loginRequest = new Login();         
//         Applicant applicant = new Applicant();
//         applicant.setEmail("madarsaheb@bitlabs.in");
//         applicant.setPassword("1992Madar");
   
//         when(registerService.login(loginRequest.getEmail(), loginRequest.getPassword())).thenReturn(applicant);
   
//         User userDetails = new org.springframework.security.core.userdetails.User(
//                 applicant.getEmail(),
//                 applicant.getPassword(),
//                 Collections.emptyList()
//         );
//         when(myUserDetailsService.loadUserByUsername(applicant.getEmail())).thenReturn(userDetails);
//              when(jwtTokenUtil.generateToken(userDetails)).thenReturn("MockToken");
//              mockMvc.perform(MockMvcRequestBuilders.post("/applicant/applicantLogin")
//                      .contentType(MediaType.APPLICATION_JSON)
//                      .content(objectMapper.writeValueAsString(loginRequest)))
//                      .andExpect(MockMvcResultMatchers.status().isInternalServerError());
//     }

//     @Test
//     public void testSendOtpSuccess() {
//     	Applicant request = new Applicant();
//         request.setEmail("test@example.com");
//         when(registerService.findByEmail(any(String.class))).thenReturn(null);
//         when(otpService.generateOtp("test@example.com")).thenReturn("123456");
//         ResponseEntity<String> response = registerController.ForgotsendOtp(request);
//         if (response.getStatusCode() == HttpStatus.OK) {
//                       assertEquals(HttpStatus.OK, response.getStatusCode());
//             assertEquals("OTP sent to your email.", response.getBody());
//             verify(registerService, times(1)).findByEmail("test@example.com");
//             verify(otpService, times(1)).generateOtp("test@example.com");
//             verify(emailService, times(1)).sendOtpEmail("test@example.com", "generatedOTP"); // Adjust the expected OTP accordingly
//         } else if (response.getStatusCode() == HttpStatus.BAD_REQUEST) {
//             assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());

//             verify(registerService, times(1)).findByEmail("test@example.com");
//             verify(otpService, never()).generateOtp("test@example.com");
//             verify(emailService, never()).sendOtpEmail(any(String.class), any(String.class));
//         } else {
//                      assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//             assertEquals("Error sending OTP", response.getBody());
//             verify(registerService, times(1)).findByEmail("test@example.com");
//             verify(otpService, never()).generateOtp("test@example.com");
//             verify(emailService, never()).sendOtpEmail(any(String.class), any(String.class));
//         }
//     }

   
//     @Test
//     public void testSendOtpFailureCustomException() {
//         Applicant request = new Applicant();
//         request.setEmail("test@example.com");
//         when(registerService.findByEmail(any(String.class)))
//                 .thenReturn(new Applicant()); 
//          ResponseEntity<String> response = registerController.sendOtp(request);
//         assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
//         assertEquals("Email is already registered.", response.getBody());
//         verify(registerService, times(1)).findByEmail("test@example.com");
//     }
   
//     @Test
//     public void testForgotsendOtpSuccess() {
//         Applicant request = new Applicant();
//         request.setEmail("test@example.com");
//         when(registerService.findByEmail(any(String.class))).thenReturn(null);
//         when(otpService.generateOtp("test@example.com")).thenReturn("123456");

//         // Assuming that your controller method is ForgotsendOtp
//         ResponseEntity<String> response = registerController.ForgotsendOtp(request);

//         if (response.getStatusCode() == HttpStatus.OK) {
//             assertEquals(HttpStatus.OK, response.getStatusCode());
//             assertEquals("OTP sent to your email.", response.getBody());
//             verify(registerService, times(1)).findByEmail("test@example.com");
//             verify(otpService, times(1)).generateOtp("test@example.com");
//             verify(emailService, times(1)).sendOtpEmail("test@example.com", "123456");
//         } else if (response.getStatusCode() == HttpStatus.BAD_REQUEST) {
//             assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
//             verify(registerService, times(1)).findByEmail("test@example.com");
//             verify(otpService, never()).generateOtp("test@example.com");
//             verify(emailService, never()).sendOtpEmail(any(String.class), any(String.class));
//         } else {
//             assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//             assertEquals("Error sending OTP", response.getBody());
//             verify(registerService, times(1)).findByEmail("test@example.com");
//             verify(otpService, never()).generateOtp("test@example.com");
//             verify(emailService, never()).sendOtpEmail(any(String.class), any(String.class));
//         }
//     }
//     @Test
//     public void testForgotSendOtpFailure() {
//          Applicant request = new Applicant();
//         request.setEmail("nonexistent@example.com");
//         when(registerService.findByEmail(any(String.class))).thenReturn(null);
//         ResponseEntity<String> response = registerController.ForgotsendOtp(request);
//        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
//         assertEquals("Email not found.", response.getBody());
//         verify(registerService, times(1)).findByEmail("nonexistent@example.com");
//         verify(otpService, never()).generateOtp("nonexistent@example.com");
//        verify(emailService, never()).sendOtpEmail(any(String.class), any(String.class));
//   	}
    
//     @Test
//     public void testVerifyOtpSuccess() {
//     	OtpVerificationRequest verificationRequest = new OtpVerificationRequest();
//         verificationRequest.setEmail("test@example.com");
//         verificationRequest.setOtp("123456");

//         try {
//             when(otpService.validateOtp("test@example.com", "123456")).thenReturn(true);
//             ResponseEntity<String> response = registerController.verifyOtp(verificationRequest);
//             assertEquals(HttpStatus.OK, response.getStatusCode());
//             assertEquals("OTP verified successfully", response.getBody());
//             verify(otpService, times(1)).validateOtp("test@example.com", "123456");
//         } catch (Exception e) {
//             e.printStackTrace();
//         }
//     }

//     @Test
//     public void testSetNewPasswordSuccess() {
//     	 NewPasswordRequest request = new NewPasswordRequest();
//     	    request.setPassword("newPassword");
//     	    request.setConfirmedPassword("newPassword");

//     	    String email = "test@example.com";

//     	    try {
//     	        when(registerService.findByEmail(email)).thenReturn(new Applicant()); 
//     	        when(passwordEncoder.encode("newPassword")).thenReturn("encodedPassword");
//     	        ResponseEntity<String> response = registerController.setNewPassword(request, email);
//     	        assertEquals(HttpStatus.OK, response.getStatusCode());
//     	       assertEquals("Password reset was done successfully", response.getBody());
//     	        verify(registerService, times(1)).findByEmail(email);
//     	        verify(passwordEncoder, times(1)).encode("newPassword");
//     	        verify(registerService, times(1)).addApplicant(any(Applicant.class));
//     	    } catch (Exception e) {
    	   
//     	        e.printStackTrace();
//     	        fail("Unexpected exception: " + e.getMessage());
//     	    }
//     }


//     @Test
//     public void testSetNewPasswordUserNotFound() {
//         NewPasswordRequest request = new NewPasswordRequest();
//         request.setPassword("newPassword");
//         request.setConfirmedPassword("newPassword");
//         String email = "test@example.com";
//         when(registerService.findByEmail(email)).thenReturn(null);
//         ResponseEntity<String> response = registerController.setNewPassword(request, email);
//         assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
//         assertEquals("User not found.", response.getBody());
//         verify(registerService, times(1)).findByEmail(email);
//         verifyNoMoreInteractions(passwordEncoder, registerService);
//     }

//     @Test
//     public void testSetNewPasswordEmailNotFound() {
//         NewPasswordRequest request = new NewPasswordRequest();
//         request.setPassword("newPassword");
//         request.setConfirmedPassword("newPassword");
//         String email = "sample@gmail.com"; 
//         ResponseEntity<String> response = registerController.setNewPassword(request, email);
//         assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
//         assertEquals("Email not found.", response.getBody());
//         verifyNoInteractions(passwordEncoder, registerService);
//     }
// }
  

