package com.talentstream.dto;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;

public class LoginDTO {

	@NotBlank(message = "Email is required.")
	@Pattern(regexp = "^$|^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$", message = "Invalid email format and white spaces are not allowed.")
	private String email;

	private String password;
	
	private String iv;

	public String getIv() {
		return iv;
	}

	public void setIv(String iv) {
		this.iv = iv;
	}

	private String status = "active";

	private String utmSource;
	
	public String getUtmSource() {
		return utmSource;
	}

	public void setUtmSource(String utmSource) {
		this.utmSource = utmSource;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

}
