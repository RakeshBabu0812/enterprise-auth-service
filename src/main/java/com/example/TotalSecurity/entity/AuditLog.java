package com.example.TotalSecurity.entity;

import java.time.LocalDateTime;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;



@Entity
@Table(name="aduit_logs")
public class AuditLog{
	
    @Id
    @GeneratedValue(strategy=GenerationType.IDENTITY)
	private Long id;
    
    
    private String email;
    
    private String eventType;
    
    private String ipAddress;
    
    private LocalDateTime createdAt;
    
   @PrePersist    
    public void onCreate() {
    	this.createdAt=LocalDateTime.now();

    }

   

public Long getId() {
	return id;
}

public void setId(Long id) {
	this.id = id;
}

public String getEmail() {
	return email;
}

public void setEmail(String email) {
	this.email = email;
}

public String getEventType() {
	return eventType;
}

public void setEventType(String eventType) {
	this.eventType = eventType;
}

public String getIpAddress() {
	return ipAddress;
}

public void setIpAddress(String ipAddress) {
	this.ipAddress = ipAddress;
}

public LocalDateTime getCreatedAt() {
	return createdAt;
}

public void setCreatedAt(LocalDateTime createdAt) {
	this.createdAt = createdAt;
}
   
    
    
	
	
	
	
	
	
	
	
	
}
