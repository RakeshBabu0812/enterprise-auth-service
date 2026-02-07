package com.example.TotalSecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
public class AdminController {
	
	
	@GetMapping("/welcome")
	public String welcome() {
	
		
		return "Hello Admin how are you ";
	}
	
	
	
	

}
