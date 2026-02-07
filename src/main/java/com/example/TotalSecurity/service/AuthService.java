package com.example.TotalSecurity.service;

import java.time.Duration;
import java.util.List;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.TotalSecurity.dto.AuthResponse;
import com.example.TotalSecurity.dto.ChangePasswordRequest;
import com.example.TotalSecurity.dto.ForgotPasswordRequest;
import com.example.TotalSecurity.dto.LoginRequest;
import com.example.TotalSecurity.dto.RefreshTokenRequest;
import com.example.TotalSecurity.dto.RegisterRequest;
import com.example.TotalSecurity.dto.ResetPasswordRequest;
import com.example.TotalSecurity.entity.AuthProvider;
import com.example.TotalSecurity.entity.Role;
import com.example.TotalSecurity.entity.Users;
import com.example.TotalSecurity.exception.EmailAlreadyExistsException;
import com.example.TotalSecurity.exception.TooManyRequestException;
import com.example.TotalSecurity.hash.TokenHashUtil;
import com.example.TotalSecurity.repo.UserRepository;
import com.example.TotalSecurity.security.JwtService;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bucket4j;
import io.github.bucket4j.Refill;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

@Service
public class AuthService {

	
	private final UserRepository repo;
    private final PasswordEncoder encoder;
    private final JwtService jwt;
    
    private final EmailService emailService;

    
    private final AuditLogService auditService;
    
    
    private final Map<String,Bucket> resendBuckets= new ConcurrentHashMap<>();
    
    
    
    public AuthService(UserRepository repo,
                       PasswordEncoder encoder,
                       JwtService jwt,EmailService emailService,AuditLogService auditService) {
        this.repo = repo;
        this.encoder = encoder;
        this.jwt = jwt;
        this.emailService=emailService;
        this.auditService=auditService;
        
    }
	
    
    public void register(RegisterRequest req) {
    	
        if (repo.findByEmail(req.email).isPresent()) {
        	  throw new EmailAlreadyExistsException("Email already registered okay try different");
        }
        
        Users user = new Users();
        user.setEmail(req.email);
        user.setPassword(encoder.encode(req.password));
        user.setRole(Role.USER);
        user.setProvider(AuthProvider.LOCAL);
        
        user.setEnabled(false);
        
       String token=UUID.randomUUID().toString();
       
       user.setEmailVerificationToken(token);
       user.setEmailVerificationExpiry(LocalDateTime.now().plusHours(24));
       
   
        repo.save(user);
        
        String verificationLink="http://localhost:8080/api/auth/verify-email?token="+token;
        
        
        emailService.sendVerificationLink(user.getEmail(),verificationLink);
        
        
    
   
    }
    
    public AuthResponse login(LoginRequest req,String ip) {
    	
    	
    	
        Users user = repo.findByEmail(req.email)
                .orElseThrow(() -> {
                	
                	auditService.log(req.email, "LOGIN_FAILURE", ip);
  
                return new BadCredentialsException("Invalid credentials");
                			
                });
        
      
        if(user.getAccountLockedUntil()!=null && user.getAccountLockedUntil().isBefore(LocalDateTime.now())) {
        	
        	user.unLockAccount();
        	repo.save(user);
        	
  
        }
        
        if(user.isAccountLocked()) {
        	
        	auditService.log(user.getEmail(), "ACCOUNT_LOCKED", ip);
        	
        	throw new RuntimeException("Invalid credientials or Account temporarily locked");
        }
        
        if(!user.isEnabled()) {
        	throw new RuntimeException("Please verify your email before login");
        
        }
        if(user.getProvider()==AuthProvider.GOOGLE) {
        	throw new RuntimeException("Please login Using Google");
        }
       
        

        if (!encoder.matches(req.password, user.getPassword())) {
        	
        	int attempts=user.getFailedLoginAttempts()+1;
        	
        	user.setFailedLoginAttempts(attempts);
        	
        	if(attempts>=5) {
        		user.setAccountLockedUntil(LocalDateTime.now().plusMinutes(15));
        		auditService.log(user.getEmail(),"ACCOUNT_LOCKED", ip);
   
        	}
        	else {
        		auditService.log(user.getEmail(), "LOGIN_FAILURE", ip);
        	}
        
        	 repo.save(user);
        	 
        	throw new BadCredentialsException("Invalid credentials or Account temporarily locked");
            
        }
        
        user.unLockAccount();
        
        
        auditService.log(user.getEmail(), "LOGIN_SUCCESS", ip);
   //     repo.save(user);
        

        
         String accesstoken=jwt.generateAccessToken(user.getEmail(),user.getRole().name());
          String refreshtoken=jwt.generateRefreshToken(user.getEmail());
          
    //      String refreshHashToken=encoder.encode(refreshtoken);
          
      //    user.setRefreshTokenHash(refreshHashToken);
          
          String refreshHashToken=TokenHashUtil.hash(refreshtoken);
          
          user.setRefreshTokenHash(refreshHashToken);

               
          repo.save(user);
          
          return new AuthResponse(accesstoken,refreshtoken);
     
        
    }
    
    public AuthResponse refresh(RefreshTokenRequest req) {
        String email = jwt.extractEmail(req.refreshToken); 
        
        
        Users user=repo.findByEmail(email).orElseThrow(()->new RuntimeException("Invalid Refresh token"));
        
        
        String incomingHash=TokenHashUtil.hash(req.refreshToken);
        String storedHash=user.getRefreshTokenHash();
        
        
        
    /*    if(user.getRefreshTokenHash()==null || !encoder.matches(req.refreshToken, user.getRefreshTokenHash())) {
        	
        	throw new RuntimeException("Refresh token reuse detected");
        	
        }*/
        
        
        if(storedHash==null || !TokenHashUtil.constantTimeEquals(incomingHash, storedHash) ) {
        	
        	throw new RuntimeException("Refresh token reuse detected");
        
        }
        
        String newaccesstoken=jwt.generateAccessToken(email,user.getRole().name());
        String newrefreshtoken=jwt.generateRefreshToken(email);
        
        
    //  user.setRefreshTokenHash(encoder.encode(newrefreshtoken));
       
          user.setRefreshTokenHash(TokenHashUtil.hash(newrefreshtoken));
         
        repo.save(user);
        
    
        return new AuthResponse(newaccesstoken,newrefreshtoken);
     
    }
    public void forgotPassword(ForgotPasswordRequest req) {
    	
    

        Users user = repo.findByEmail(req.email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String token = UUID.randomUUID().toString();

        user.setResetPasswordToken(token);
        user.setResetPasswordExpiry(LocalDateTime.now().plusMinutes(10));
        
        repo.save(user);
        
 
        String resetLink = "http://localhost:3000/reset-password?token=" + token;
        
        emailService.sendResetPasswordEmail(user.getEmail(), resetLink);
    }
    
    
    public void resetPassword(ResetPasswordRequest req,String ip) {

        Users user = repo.findByResetPasswordToken(req.token)
                .orElseThrow(() -> new RuntimeException("Invalid token"));

        if (user.getResetPasswordExpiry().isBefore(LocalDateTime.now()))
            throw new RuntimeException("Token expired");

        user.setPassword(encoder.encode(req.password));
        
        user.setPasswordChangedAt(LocalDateTime.now());
        user.setRefreshTokenHash(null);
        

        // invalidate token (VERY IMPORTANT)
        user.setResetPasswordToken(null);
        user.setResetPasswordExpiry(null);

        repo.save(user);
        auditService.log(user.getEmail(),"PASSWORD_RESET",ip);
    }


	public void changePassword(String email,ChangePasswordRequest req,String ip) {
	
		 Users user = repo.findByEmail(email)
		            .orElseThrow(() -> new RuntimeException("User not found"));
		 
		 
		 if(user.getPassword()!=null) {
			 
			 if(req.getCurrentPassword()==null || req.getCurrentPassword().isBlank()) {

			        throw new RuntimeException("Current password is required");
			 }
			 
			 
			 if(!encoder.matches(req.getCurrentPassword(),user.getPassword())) {
				 
				 auditService.log(email,"PASSWORD_CHANGE_FAILED",ip);
				
				 throw new RuntimeException("Current password is wrong");
			 } 
		 }
		 
		 if(user.getPassword()!=null && encoder.matches(req.getNewPassword(), user.getPassword())) {
			 
			 throw new RuntimeException("New password cant be same as old password");
		 }
		 
		
		    user.setPassword(encoder.encode(req.getNewPassword()));
		    user.setPasswordChangedAt(LocalDateTime.now());
		    user.setTokenInvalidatedAt(LocalDateTime.now());
		    
		    user.setRefreshTokenHash(null);
		 
		    
		    repo.save(user);
		    auditService.log(email, "PASSWORD_CHANGED", ip);
	}
	
	public void logout(String email,String ip) {

	    Users user = repo.findByEmail(email)
	            .orElseThrow(() -> new RuntimeException("User not found"));
	    
	    auditService.log(email, "LOGOUT", ip);

	    user.setTokenInvalidatedAt(LocalDateTime.now());
	 

	    user.setRefreshTokenHash(null);
	  
	    
	    repo.save(user);
	    
	}


	public void verifyEmail(String token) {
		
		Users user=repo.findByEmailVerificationToken(token).orElseThrow(()->new RuntimeException("Invalid Verification Token"));
		
		
		if(user.getEmailVerificationExpiry().isBefore(LocalDateTime.now())) {
			
			throw new RuntimeException("Verification token Expired");
	
		}
		
		user.setEnabled(true);
		user.setEmailVerificationToken(null);
		user.setEmailVerificationExpiry(null);
	
	     repo.save(user);
	     
	     
		
	}


	public void resendVerification(String email) {
		
		
		Bucket bucket=resendBuckets.computeIfAbsent("resend:"+email,k->Bucket4j.builder()
				.addLimit(Bandwidth.classic(3, 
						
						Refill.intervally(3, Duration.ofMinutes(10))
						
						
						)
						
						
						).build()
				);
		if(!bucket.tryConsume(1)) {
			
			throw new TooManyRequestException("Too Many resend attempts.Try again later.");
			
		}
		
		Users user=repo.findByEmail(email).orElseThrow(()-> new RuntimeException("User not found"));
		
		if(user.isEnabled()) {
			return;
		}
		
		String token=UUID.randomUUID().toString();
		
		user.setEmailVerificationToken(token);
		user.setEmailVerificationExpiry(LocalDateTime.now().plusHours(24));
		
		repo.save(user);
		
		
		String verificationLink="localhost:8080/api/auth/verify-email?token="+token;
		
		emailService.sendVerificationLink(email, verificationLink);
		
	}


	public AuthResponse googleLogin(String idTokenString) {
		
		try {
		GoogleIdTokenVerifier verifier=new GoogleIdTokenVerifier.Builder(
				new NetHttpTransport(),JacksonFactory.getDefaultInstance()).setAudience(List.of("your_client_id")).build();
		
		GoogleIdToken idToken=verifier.verify(idTokenString);
		
		if(idToken==null) {
			throw new RuntimeException("Invalid Google Login");
			
		}
		GoogleIdToken.Payload payload=idToken.getPayload();
		
		String email=payload.getEmail();
		
		String name=(String)payload.get("name");
		
		   
		if(!payload.getEmailVerified()) {
			
			throw new RuntimeException("Google Email is not verified");
			
		}
		
		Users user=repo.findByEmail(email).orElse(null);
		
		if(user==null) {
			
			user=new Users();
			user.setEmail(email);
			user.setEnabled(true);
			user.setRole(Role.USER);
			user.setProvider(AuthProvider.GOOGLE);
			user.setPassword(null);
			
			repo.save(user);
			
		}
		
		else {
			if(!user.isEnabled()) {
				user.setEnabled(true);
				user.setEmailVerificationToken(null);
				user.setEmailVerificationExpiry(null);
				repo.save(user);
			}
			
		}
		
		String accessToken=jwt.generateAccessToken(email, user.getRole().name());
		
		String refreshToken=jwt.generateRefreshToken(email);
		
		
		user.setRefreshTokenHash(TokenHashUtil.hash(refreshToken));
		
		
		repo.save(user);
		
		
	

		return new AuthResponse(accessToken,refreshToken);
		
	
		
		}
		
		 catch (Exception e) {
		        throw new RuntimeException("Google authentication failed");
		    }
		
		
		
	}
	



	
	
	
    

    
    
    
    
    
    
    
    
    
	
	
	
	
	
	
	
}
