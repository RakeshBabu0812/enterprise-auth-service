package com.example.TotalSecurity.security;

import java.io.IOException;
import java.util.List;

import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.TotalSecurity.entity.Users;
import com.example.TotalSecurity.repo.UserRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


@Component
@Order(2)
public class JwtAuthenticationFilter extends OncePerRequestFilter {
	
	
	 private final JwtService jwtService;

	 private final UserRepository repo;
	 
	    public JwtAuthenticationFilter(JwtService jwtService,UserRepository repo) {
	        this.jwtService = jwtService;
	        this.repo=repo;
	    }
	    
	    @Override
	    protected boolean shouldNotFilter(HttpServletRequest request) {
	        String path = request.getServletPath();

	        return path.startsWith("/api/auth/login")
	            || path.startsWith("/api/auth/register")
	            || path.startsWith("/api/auth/forgot-password")
	            || path.startsWith("/api/auth/reset-password")
	            || path.startsWith("/api/auth/refresh")
	            || path.startsWith("/api/auth/verify-email")
	            || path.startsWith("/api/auth/resend-verification")
	            ||  path.startsWith("/v3/api-docs") ||
	            path.startsWith("/swagger-ui") ||
	            path.startsWith("/swagger-ui.html");
	            
	        
	        
	    }

	    

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		String header = request.getHeader("Authorization");

        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
           
            try {
                String email = jwtService.extractEmail(token);

                if (email != null &&
                    SecurityContextHolder.getContext().getAuthentication() == null) {
                	
                	  Users user = repo.findByEmail(email).orElse(null);
                	  
                	  
                	  if (user != null && jwtService.isTokenValid(token, user)) {
                		  
                		  String role=jwtService.extractRole(token);
                	
                		  List<SimpleGrantedAuthority> authorities=List.of(new SimpleGrantedAuthority("ROLE_"+role));

                          UsernamePasswordAuthenticationToken authentication =
                                  new UsernamePasswordAuthenticationToken(
                                          email,
                                          null,
                                          authorities
                                  );

                          SecurityContextHolder.getContext()
                                  .setAuthentication(authentication);
                      }
                }

            } catch (Exception ex) {
            	throw new RuntimeException("something happend in JwtFilter");
           	
            }
          
            
           
        }

        filterChain.doFilter(request, response);
		
		
		
	}
	
	
	

	
	
	
	
	
	

}
