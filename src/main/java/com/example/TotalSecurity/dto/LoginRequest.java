package com.example.TotalSecurity.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;


public class LoginRequest {
	
	
	   @Email(message="Invalid Email Format")
	  @NotBlank(message="Email is Required")
	  public String email;
	 
	  @NotBlank(message="password is Required")
	  public String password;
	   

}
