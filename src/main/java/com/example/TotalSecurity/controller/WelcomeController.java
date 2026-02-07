
package com.example.TotalSecurity.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@RestController
public class WelcomeController {
	

    private static final Logger log =
            LoggerFactory.getLogger(WelcomeController.class);
    
	@GetMapping("/api/welcome")
	public String welcome(Authentication authentication ) {

		String email=authentication.getName();
		//System.out.println("this is from welocme");
		  log.info("THIS IS FROM WELCOME CONTROLLER");
		  
			
		 return "Welcome " + email + "! You are successfully authenticated.";
	}
	
	@GetMapping("/test")
	public String test() {
	    throw new RuntimeException("FORCE CONSOLE OUTPUT");
	}
 

}
