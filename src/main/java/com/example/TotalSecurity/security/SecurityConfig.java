package com.example.TotalSecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.TotalSecurity.exception.JwtAuthEntryPoint;

@Configuration
@EnableWebSecurity    //===> not needed for older versions thats why i commented
@EnableMethodSecurity
public class SecurityConfig {
	
	
   @Autowired
	private JwtAuthEntryPoint jwtAuthEntryPoint;
	
	
	@Autowired
	private RateLimitFilter rateLimitFilter;
	
	
	
	 @Bean
	    public SecurityFilterChain filterChain(HttpSecurity http,
	                                           JwtAuthenticationFilter jwtFilter) throws Exception {

	        http.csrf(csrf -> csrf.disable())
	            .authorizeHttpRequests(auth -> auth
	            		  .requestMatchers(
	            		          "/api/auth/register",
	            		          "/api/auth/login",
	            		          "/api/auth/refresh",
	            		          "/api/auth/forgot-password",
	            		          "/api/auth/reset-password",
	            		          "/api/auth/verify-email",
	            		          "/api/auth/resend-verification",
	            		          "/api/auth/google",
	            		          "/v3/api-docs/**",
	            		          "/swagger-ui/**",
	            		          "/swagger-ui.html"
	            		      ).permitAll()
	            		      // PROTECTED endpoints
	            		      .requestMatchers(
	            		          "/api/auth/change-password",
	            		          "/api/auth/logout"
	            		      ).authenticated()
	            		      .requestMatchers("/api/admin/**").hasRole("ADMIN")
	                .anyRequest().authenticated()
	            ).exceptionHandling(ex->ex.authenticationEntryPoint(jwtAuthEntryPoint))
	            .addFilterBefore(jwtFilter,
	                    UsernamePasswordAuthenticationFilter.class);
	        

	        return http.build();
	    }

	    @Bean
	    public PasswordEncoder passwordEncoder() {
	        return new BCryptPasswordEncoder();
	    }
	    
	   
	    @Bean
	    public RoleHierarchy roleHierarchy() {
	    	
	    	RoleHierarchyImpl roleHierarchy=new RoleHierarchyImpl();
	    	
	    	
	    	roleHierarchy.setHierarchy(
	    			"""
	    			ROLE_ADMIN > ROLE_USER
	    			"""
	    	
	    			);
	    	return roleHierarchy;
	    	
	    }
	    
	    @Bean
	    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(RoleHierarchy roleHierarchy) {
	    	
	    	DefaultMethodSecurityExpressionHandler handler=new DefaultMethodSecurityExpressionHandler();
	    	
	    	handler.setRoleHierarchy(roleHierarchy);
	    	
                return handler;	    
	    	
	    }
	    
	    
	

}
