package com.talentstream.exception;

public class ErrorException extends RuntimeException{
		private static final long serialVersionUID = 1L;
	private String message;
	
	

	public ErrorException(String message) {
		super();
		this.message = message;
	}

	public ErrorException() {
		super();
		
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}
 
	
	
}
