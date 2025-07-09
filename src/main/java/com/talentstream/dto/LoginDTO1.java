package com.talentstream.dto;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;

public class LoginDTO1 {

	@NotBlank(message = "Email is required.")
    @Pattern(
            regexp = "^$|^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$",
            message = "Invalid email format and white spaces are not allowed."
        )
	private String email;

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}
	
}
