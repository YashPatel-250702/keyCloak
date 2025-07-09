package com.talentstream.entity;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

public class PasswordRequest {
	public PasswordRequest() {
		super();

	}

	@NotBlank(message = "New password required.")
	@Size(min = 6, message = "New password must be at least 6 characters long.")
	@Pattern(regexp = "^$|^(?=.{6,}$)(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*(),.?\":{}|<>])(?!.*\\s).*$", message = "New password must be at least 6 characters long and contain at least one uppercase letter, one digit, one special character, and no white spaces.")
	private String newPassword;
	@NotBlank(message = "Old password required.")
	@Size(min = 6, message = "Old password must be at least 6 characters long.")
	@Pattern(regexp = "^$|^(?=.{6,}$)(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*(),.?\":{}|<>])(?!.*\\s).*$", message = "Old password must be at least 6 characters long and contain at least one uppercase letter, one digit, one special character, and no white spaces.")
	private String oldPassword;
	
	private String ivOld;
    private String ivNew;
    
    

	public String getIvOld() {
		return ivOld;
	}

	public void setIvOld(String ivOld) {
		this.ivOld = ivOld;
	}

	public String getIvNew() {
		return ivNew;
	}

	public void setIvNew(String ivNew) {
		this.ivNew = ivNew;
	}

	public String getNewPassword() {
		return newPassword;
	}

	public void setNewPassword(String newPassword) {
		this.newPassword = newPassword;
	}

	public String getOldPassword() {
		return oldPassword;
	}

	public void setOldPassword(String oldPassword) {
		this.oldPassword = oldPassword;
	}
}