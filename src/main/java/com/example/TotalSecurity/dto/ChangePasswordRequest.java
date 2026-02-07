package com.example.TotalSecurity.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class ChangePasswordRequest {
	
	@NotBlank(message="Newpassword is required")
	@Size(min=4,message="password must be atleast 4 letters")
	private String newPassword;
	
	
	private String currentPassword;
	
	public String getCurrentPassword() {
		return currentPassword;
		
	}

    public String getNewPassword() {
        return newPassword;
    }
    

}
