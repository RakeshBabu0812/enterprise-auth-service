package com.example.TotalSecurity.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class RegisterRequest {
	
	
	 @Email(message="Invalid email Format")
	 @NotBlank(message="Email is required")
	  public String email;
	  
	 
	  @NotBlank(message="password is required")
	   @Size(min=4,message="password must be atleast 4 charcters")
	 public String password;


}
