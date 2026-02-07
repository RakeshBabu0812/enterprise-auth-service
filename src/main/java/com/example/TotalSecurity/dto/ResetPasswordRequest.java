package com.example.TotalSecurity.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class ResetPasswordRequest {

	@NotBlank(message="token is required")
	public String token;
	
   @NotBlank(message="password is requierd")
   @Size(min=4,message="password must be 4 letters")
	public String password;
	
	
}
