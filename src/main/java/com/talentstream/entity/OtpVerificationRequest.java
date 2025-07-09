package com.talentstream.entity;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

public class OtpVerificationRequest {

	public OtpVerificationRequest() {
		super();

	}

	@NotBlank(message = "OTP is required.")
	@Size(min = 6, message = "OTP must be at least 6 characters long.")
	private String otp;
	@NotBlank(message = "Email is required.")
	@Pattern(regexp = "^$|^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$", message = "Invalid email format and white spaces are not allowed.")
	private String email;

	public String getOtp() {
		return otp;
	}

	public void setOtp(String otp) {
		this.otp = otp;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public OtpVerificationRequest(String otp, String email) {
		super();
		this.otp = otp;
		this.email = email;
	}

}
