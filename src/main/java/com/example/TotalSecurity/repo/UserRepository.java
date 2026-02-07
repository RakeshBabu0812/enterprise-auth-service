package com.example.TotalSecurity.repo;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.TotalSecurity.entity.Users;

public interface UserRepository  extends JpaRepository<Users,Long>{
	
	
	 Optional<Users> findByEmail(String email);

	 
	 Optional<Users> findByResetPasswordToken(String token);
	 
	 Optional<Users> findByEmailVerificationToken(String token);
	 
	 
	

}
