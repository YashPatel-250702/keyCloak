package com.talentstream.entity;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

public class NewPasswordRequest {

	public NewPasswordRequest() {
		super();

	}

	@NotBlank(message = "Password required.")
	@Size(min = 6, message = "Password must be at least 6 characters long.")
	@Pattern(regexp = "^$|^(?=.{6,}$)(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*(),.?\":{}|<>])(?!.*\\s).*$", message = "Password must be at least 6 characters long and contain at least one uppercase letter, one digit, one special character, and no white spaces.")
	private String password;
	@NotBlank(message = "ConfirmPassword required.")
	@Size(min = 6, message = "ConfirmPassword must be at least 6 characters long.")
	@Pattern(regexp = "^$|^(?=.{6,}$)(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*(),.?\":{}|<>])(?!.*\\s).*$", message = "Password must be at least 6 characters long and contain at least one uppercase letter, one digit, one special character, and no white spaces.")
	private String confirmedPassword;

	public String getConfirmedPassword() {
		return confirmedPassword;
	}

	public void setConfirmedPassword(String confirmedPassword) {
		this.confirmedPassword = confirmedPassword;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public NewPasswordRequest(String password, String confirmedPassword) {
		super();
		this.password = password;
		this.confirmedPassword = confirmedPassword;
	}

}
