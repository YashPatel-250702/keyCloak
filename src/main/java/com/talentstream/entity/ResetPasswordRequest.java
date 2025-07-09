package com.talentstream.entity;

public class ResetPasswordRequest {
    private String email;
    private String mobilenumber;
    
    
    
    
 
	public String getMobilenumber() {
		return mobilenumber;
	}
 
	public void setMobilenumber(String mobilenumber) {
		this.mobilenumber = mobilenumber;
	}
 
	public String getEmail() {
		return email;
	}
 
	public void setEmail(String email) {
		this.email = email;
	}
 
	public ResetPasswordRequest(String email) {
		super();
		this.email = email;
	}
 
	public ResetPasswordRequest() {
		super();
	}
   
   
    
}