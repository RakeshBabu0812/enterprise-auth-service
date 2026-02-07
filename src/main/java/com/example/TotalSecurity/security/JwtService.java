package com.example.TotalSecurity.security;

import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import com.example.TotalSecurity.entity.Users;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;


@Service
public class JwtService {
	
	private String SECRET = "";
    
	private final long ACCESS_EXP = 1000 * 60 * 15;   // 15 min
    
    private final long REFRESH_EXP = 1000 * 60 * 60 * 24 * 7; // 7 days
    
	
	public JwtService() {
		try {
			KeyGenerator keyGen=KeyGenerator.getInstance("HmacSHA256");			
			SecretKey sk=keyGen.generateKey();
		  SECRET=Base64.getEncoder().encodeToString(sk.getEncoded());
		
		} 
		
		catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			throw new RuntimeException(e);
		}
		
	}
	private SecretKey getKey() {
		byte [] keyBytes=Decoders.BASE64.decode(SECRET);
		
		return Keys.hmacShaKeyFor(keyBytes);

	
	}
	
    
    
 
    
    public String generateAccessToken(String email,String role) {
        return Jwts.builder()
                .setSubject(email)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + ACCESS_EXP))
                .signWith(getKey())
                .compact();
    }
    

    public String generateRefreshToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_EXP))
                .signWith(getKey())
                .compact();
    }
    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    
    public String extractRole(String token) {
    	
    	return getClaims(token).get("role", String.class);
    
    }
    
    public String extractEmail(String token) {
        return getClaims(token).getSubject();
    }
    

	public boolean isTokenValid(String token, Users user) {
	
		Claims claims = getClaims(token);
		
		 
		Date issuedAt = claims.getIssuedAt();
		
		 if (user.getPasswordChangedAt() != null ) {
			 
			 Instant passwordChangedInstant=user.getPasswordChangedAt().atZone(ZoneId.systemDefault()).toInstant();
			 
			 if(issuedAt.toInstant().isBefore(passwordChangedInstant)) {
		            
		            return false; // 🔥 token issued before password reset
		       
		             }
		 }

		  if (user.getTokenInvalidatedAt() != null ) {
			       
			     Instant tokenInvalidatedAtInstant=user.getTokenInvalidatedAt().atZone(ZoneId.systemDefault()).toInstant();
			     
			     if(issuedAt.toInstant().isBefore(tokenInvalidatedAtInstant)) {
			        return false;
			     }
			     
			    }
		  
		
		return true;
	}
    
    
	
    
    
    
    
    
	
	
	
	
	

}
