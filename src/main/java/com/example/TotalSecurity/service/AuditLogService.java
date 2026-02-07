package com.example.TotalSecurity.service;

import org.springframework.stereotype.Service;

import com.example.TotalSecurity.entity.AuditLog;
import com.example.TotalSecurity.repo.AuditLogRepository;

@Service
public class AuditLogService {
	
	
	private final AuditLogRepository repo;
	  
	public AuditLogService(AuditLogRepository repo) {
	        this.repo = repo;
	    
	  }
	
	public void log(String email,String eventType,String ipAddress) {
		
		AuditLog log=new AuditLog();
		
		log.setEmail(email);
		log.setEventType(eventType);
		log.setIpAddress(ipAddress);
		
		repo.save(log);
		
		
		
		
		
		
	}
	
	

}
