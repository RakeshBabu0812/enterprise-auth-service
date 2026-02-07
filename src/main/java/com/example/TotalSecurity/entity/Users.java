package com.example.TotalSecurity.entity;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;



@Entity
@Table(name="users")
public class Users {
	
	     @Id
	    @GeneratedValue(strategy = GenerationType.IDENTITY)
	    private Long id;

	    @Column(unique = true, nullable = false)
	    private String email;

	    @Column(nullable = false)
	    private String password;
	    
	    @Enumerated(EnumType.STRING)
	    private Role role;
	    
	    @Enumerated(EnumType.STRING)
	    @Column(nullable=false)
	    private AuthProvider provider;
	   

	    private String resetPasswordToken;
	   
	    public AuthProvider getProvider() {
			return provider;
		}

		public void setProvider(AuthProvider provider) {
			this.provider = provider;
		}
		private LocalDateTime resetPasswordExpiry;
	    
	    
	    private boolean enabled;
	    
	    
	    private String emailVerificationToken;
	    
	    
	    private LocalDateTime emailVerificationExpiry;
	    
	    
	    
	    
	
	    
	    public boolean isEnabled() {
			return enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public String getEmailVerificationToken() {
			return emailVerificationToken;
		}

		public void setEmailVerificationToken(String emailVerificationToken) {
			this.emailVerificationToken = emailVerificationToken;
		}

		public LocalDateTime getEmailVerificationExpiry() {
			return emailVerificationExpiry;
		}

		public void setEmailVerificationExpiry(LocalDateTime emailVerificationExpiry) {
			this.emailVerificationExpiry = emailVerificationExpiry;
		}

		public Role getRole() {
			return role;
		}

		public void setRole(Role role) {
			this.role = role;
		}
		private LocalDateTime passwordChangedAt;
	    
	    private LocalDateTime tokenInvalidatedAt;
	    
	    private String refreshTokenHash;
	    
	    private int failedLoginAttempts;
	    
	    private LocalDateTime accountLockedUntil;
	    
	   
	    public int getFailedLoginAttempts() {
			return failedLoginAttempts;
		}

		public void setFailedLoginAttempts(int failedLoginAttempts) {
			this.failedLoginAttempts = failedLoginAttempts;
		}

		public LocalDateTime getAccountLockedUntil() {
			return accountLockedUntil;
		}

		public void setAccountLockedUntil(LocalDateTime accountLockedUntil) {
			this.accountLockedUntil = accountLockedUntil;
		}

		public boolean isAccountLocked() {
	    	
	    	return accountLockedUntil!=null && accountLockedUntil.isAfter(LocalDateTime.now());
	    	
	    }
	    
	    public void unLockAccount() {
	    	
	    	this.failedLoginAttempts=0;
	    	
	    	this.accountLockedUntil=null;
	    	
	    	
	    }
	    
	    
	    
	    
		public String getRefreshTokenHash() {
			return refreshTokenHash;
		}
		public void setRefreshTokenHash(String refreshTokenHash) {
			this.refreshTokenHash = refreshTokenHash;
		}
		public LocalDateTime getTokenInvalidatedAt() {
			return tokenInvalidatedAt;
		}
		public void setTokenInvalidatedAt(LocalDateTime tokenInvalidatedAt) {
			this.tokenInvalidatedAt = tokenInvalidatedAt;
		}
		public LocalDateTime getPasswordChangedAt() {
			return passwordChangedAt;
		}
		public void setPasswordChangedAt(LocalDateTime passwordChangedAt) {
			this.passwordChangedAt = passwordChangedAt;
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
		public String getPassword() {
			return password;
		}
		public void setPassword(String password) {
			this.password = password;
		}
		public String getResetPasswordToken() {
			return resetPasswordToken;
		}
		public void setResetPasswordToken(String resetPasswordToken) {
			this.resetPasswordToken = resetPasswordToken;
		}
		public LocalDateTime getResetPasswordExpiry() {
			return resetPasswordExpiry;
		}
		public void setResetPasswordExpiry(LocalDateTime resetPasswordExpiry) {
			this.resetPasswordExpiry = resetPasswordExpiry;
		}
	    
	    
	    
	    
	    
}
