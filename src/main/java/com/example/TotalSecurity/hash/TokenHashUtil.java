package com.example.TotalSecurity.hash;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class TokenHashUtil {
	
	
	public static String hash(String token) {
			
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte hashBytes[]=digest.digest(token.getBytes(StandardCharsets.UTF_8));
			
			return Base64.getEncoder().encodeToString(hashBytes);
			
		} 
		catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new RuntimeException("Failed to hash the token");
		}
		

	}
	public static boolean constantTimeEquals(String a,String b) {
		
		byte[] abytes=Base64.getDecoder().decode(a);
		byte[] bbytes=Base64.getDecoder().decode(b);
		
		return MessageDigest.isEqual(abytes, bbytes);
		
	    
		//return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8),b.getBytes(StandardCharsets.UTF_8));
	
		//you can do by getting bytes of base64 or u can decode and compare main aim is we want bytes comaparsion
		
		
	}
	
	

}
