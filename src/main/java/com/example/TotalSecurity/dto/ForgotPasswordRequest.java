package com.example.TotalSecurity.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public class ForgotPasswordRequest {
	
	
	
	@Email(message="Invalid Email format")
	@NotBlank(message="Email is Required")
	 public String email;
	 
	 

}
