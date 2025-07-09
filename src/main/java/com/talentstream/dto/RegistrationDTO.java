package com.talentstream.dto;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

public class RegistrationDTO {
	@NotBlank(message = "Full name is required.")
	@Pattern(regexp = "^$|^[a-zA-Z ]+$", message = "Please enter a valid full name without numbers or special characters.")
	@Size(min = 3, message = "Full name must be at least 3 characters long.")
	private String name;

	@NotBlank(message = "Email is required.")
	@Pattern(regexp = "^$|^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$", message = "Invalid email format and white spaces are not allowed.")
	private String email;

	@NotBlank(message = "Mobile number is required.")
	@Pattern(regexp = "^$|^[6789]\\d{9}$", message = "Mobile number should begin with 6, 7, 8, or 9 and be 10 digits long.")
	private String mobilenumber;

	@NotBlank(message = "Password is required.")
	@Size(min = 6, message = "Password must be at least 6 characters long.")
	@Pattern(regexp = "^$|^(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*(),.?\":{}|<>])(?!.*\\s).+$", message = "Password must contain at least one uppercase letter, one digit, one special character, and no white spaces.")
	private String password;

	private String appicantStatus = "Active";
	boolean localResume = false;

	private String utmSource;

	public String getUtmSource() {
		return utmSource;
	}

	public void setUtmSource(String utmSource) {
		this.utmSource = utmSource;
	}

	public boolean isLocalResume() {
		return localResume;
	}

	public void setLocalResume(boolean localResume) {
		this.localResume = localResume;
	}

	public String getAppicantStatus() {
		return appicantStatus;
	}

	public void setAppicantStatus(String appicantStatus) {
		this.appicantStatus = appicantStatus;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getMobilenumber() {
		return mobilenumber;
	}

	public void setMobilenumber(String mobilenumber) {
		this.mobilenumber = mobilenumber;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

}
