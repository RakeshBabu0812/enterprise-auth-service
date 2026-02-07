package com.example.TotalSecurity.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public class ResendVerificationRequest {
	
	
	@Email(message="Invalid Email format")
	@NotBlank(message="Email must required to verify")
	public String email;
	

}
