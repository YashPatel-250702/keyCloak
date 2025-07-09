package com.talentstream.dto;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;

public class ContactDetailsDTO {

	@NotBlank(message = "Name cannot be blank")
    @Pattern(regexp = "^$|^[a-zA-Z ]+$", message = "Please enter a valid full name without numbers or special characters.")
    private String name;
 
    @NotBlank(message = "Subject cannot be blank")
    private String subject;
 
    @NotBlank(message = "Email cannot be blank")
    @Email(message = "Invalid email format")
    private String email;
 
    @NotBlank(message = "Questions cannot be blank")
    private String questions;
 
	public String getName() {
		return name;
	}
 
	public void setName(String name) {
		this.name = name;
	}
 
	public String getSubject() {
		return subject;
	}
 
	public void setSubject(String subject) {
		this.subject = subject;
	}
 
	public String getEmail() {
		return email;
	}
 
	public void setEmail(String email) {
		this.email = email;
	}
 
	public String getQuestions() {
		return questions;
	}
 
	public void setQuestions(String questions) {
		this.questions = questions;
	}
}
