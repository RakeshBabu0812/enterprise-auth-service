package com.example.TotalSecurity.controller;


import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.TotalSecurity.dto.AuthResponse;
import com.example.TotalSecurity.dto.ChangePasswordRequest;
import com.example.TotalSecurity.dto.ForgotPasswordRequest;
import com.example.TotalSecurity.dto.GoogleLoginRequest;
import com.example.TotalSecurity.dto.LoginRequest;
import com.example.TotalSecurity.dto.RefreshTokenRequest;
import com.example.TotalSecurity.dto.RegisterRequest;
import com.example.TotalSecurity.dto.ResendVerificationRequest;
import com.example.TotalSecurity.dto.ResetPasswordRequest;
import com.example.TotalSecurity.service.AuthService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")	

public class AuthController {
	
	
	    private final AuthService service;

	    public AuthController(AuthService service) {
	        this.service = service;
	    }
	    
	    
	   @PostMapping("/register")
	   
	   public ResponseEntity<String> register(@Valid @RequestBody RegisterRequest req){
		  	    
		   System.out.println("hello this is from register");
		   
		  
		   service.register(req);
		     
		   return ResponseEntity.status(HttpStatus.CREATED).body("User Registerd successfully");
		   
	   }
	   @PostMapping("/login")
	    public ResponseEntity<AuthResponse> login(
	           @Valid @RequestBody LoginRequest req,HttpServletRequest request) {

		   System.out.println("hello this is from login");
		       
		   String ip=request.getRemoteAddr();
		   
	        AuthResponse response = service.login(req,ip);
	        return ResponseEntity.ok(response); // 200
	    }
	   
	   
	   @PostMapping("/refresh")
	    public ResponseEntity<AuthResponse> refresh(
	            @RequestBody RefreshTokenRequest req) {

	        AuthResponse response = service.refresh(req);
	        return ResponseEntity.ok(response); // 200
	    }
	   
	   @PostMapping("/forgot-password")
	    public ResponseEntity<String> forgotPassword(
	             @RequestBody ForgotPasswordRequest email) {

	        service.forgotPassword(email);

	        // Always return same response (security best practice)
	        return ResponseEntity.ok(
	                "If the email exists, a reset link has been sent"
	        );
	    }
	   
	   
	   @PostMapping("/reset-password")
	    public ResponseEntity<String> resetPassword(
	           @RequestBody ResetPasswordRequest req,HttpServletRequest request) {
		   
		     String ip=request.getRemoteAddr();
		     
	        service.resetPassword(req,ip);
	        
	        return ResponseEntity.ok("Password reset successful");
	    }
	   
	   @PostMapping("/change-password")
	   public ResponseEntity<String> changePassword(
	           @RequestBody ChangePasswordRequest req,
	           Authentication authentication,HttpServletRequest request) {
	       String email = authentication.getName(); // from JWT

	         String ip=request.getRemoteAddr();
	       service.changePassword(email,req,ip);

	       return ResponseEntity.ok("Password changed. Please login again.");
	   }

	   @PostMapping("/logout")
	   public ResponseEntity<String> logout(Authentication authentication,HttpServletRequest request) {

	       String email = authentication.getName();

	       String ip=request.getRemoteAddr();
	       service.logout(email,ip);
	       
	     
	       return ResponseEntity.ok("Logged out successfully");
	   }
	   
	   @GetMapping("/verify-email")
	   public ResponseEntity<String> verifyEmail(@RequestParam String token){
		   
		   
		   service.verifyEmail(token);
		   
		   
		  return ResponseEntity.ok("Email verification successful,Now you can login");
		   
	   }
	   
	   @PostMapping("/resend-verification")
	   
	   public ResponseEntity<String> resendVerification(@RequestBody ResendVerificationRequest req){
		   
		   service.resendVerification(req.email);
		   
		return  ResponseEntity.ok("If account exists and  is not verified ,a new verification email has been sent.");
		   
	   }
	   
	   @PostMapping("/google")
	   
	   public ResponseEntity<AuthResponse> googleLogin(@RequestBody GoogleLoginRequest request){
		   
		   
		   
		AuthResponse response=service.googleLogin(request.idToken);
		
		return ResponseEntity.ok(response);
		
		  
		   
	   }

	   
	   
	   
	   
	   
	   
	   


	    
	    
	

}
