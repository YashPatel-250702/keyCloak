package com.talentstream.entity;

import javax.persistence.Id;

public class RecruiterLogin {
	public RecruiterLogin() {
		super();

	}

	@Id
	private String email;
	private String password;
	private String iv;
	
	

	public String getIv() {
		return iv;
	}


	public void setIv(String iv) {
		this.iv = iv;
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

	public RecruiterLogin(String email, String password) {
		super();
		this.email = email;
		this.password = password;
	}

}
