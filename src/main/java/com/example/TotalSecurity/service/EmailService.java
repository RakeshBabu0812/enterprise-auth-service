package com.example.TotalSecurity.service;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
	
	 private final JavaMailSender mailSender;

	    public EmailService(JavaMailSender mailSender) {
	        this.mailSender = mailSender;
	    }
	    
	    public void sendResetPasswordEmail(String toEmail, String resetLink) {

	        SimpleMailMessage message = new SimpleMailMessage();
	        message.setTo(toEmail);
	        message.setSubject("Reset Your Password");
	        message.setText(
	                "You requested to reset your password.\n\n" +
	                "Click the link below to reset it:\n" +
	                resetLink + "\n\n" +
	                "This link will expire in 10 minutes.\n\n" +
	                "If you did not request this, please ignore this email."
	        );

	        mailSender.send(message);
	    }

		public void sendVerificationLink(String toEmail, String verificationLink) {
			
			SimpleMailMessage message=new SimpleMailMessage();
			
			message.setTo(toEmail);
			message.setSubject("Verify your Email");
			message.setText("Click the link below to verify your email:\\n\\n"+verificationLink);
			
			mailSender.send(message);	
		}
		
		
		
	    
	    
	    
	
	
	

}
