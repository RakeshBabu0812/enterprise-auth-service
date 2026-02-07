 package com.example.TotalSecurity.dto;

import jakarta.validation.constraints.NotBlank;

public class GoogleLoginRequest {
	
	
	
	@NotBlank(message="id Token must required")
	public String idToken;

	
}
