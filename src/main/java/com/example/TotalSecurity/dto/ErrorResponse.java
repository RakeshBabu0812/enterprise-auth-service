package com.example.TotalSecurity.dto;

import java.time.LocalDateTime;





public class ErrorResponse {

	
	private boolean success;
	
	private String message;
	
	private LocalDateTime timestamp;
	
	  public ErrorResponse(String message) {
	        this.success = false;
	        this.message = message;
	        this.timestamp = LocalDateTime.now();
	    }
	  
	    
	  public boolean isSuccess() {
	        return success;
	    }

	    public String getMessage() {
	        return message;
	    }

	    public LocalDateTime getTimestamp() {
	        return timestamp;
	    }
		
}