package com.example.TotalSecurity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/user")
public class UserController {
	
	
	@GetMapping("/profile")
	@PreAuthorize("hasRole('USER')")
	public String profile(Authentication authentication) {
		
		return "User Profile  is :"+authentication.getName();
		
	}
	
	@DeleteMapping("/delete-user/{email}")
	@PreAuthorize("hasRole('ADMIN')")
	public String deleteUser(@PathVariable String email) {
		return "Deleted User: "+email;
		
	}
	
	
	@GetMapping("/profile/{email}")
	@PreAuthorize("#email==authentication.name or  hasRole('ADMIN')")
	public String getProfile(@PathVariable String email) {
		
		return "Profile of: "+email;
		
		
	}
	
	
	

}
