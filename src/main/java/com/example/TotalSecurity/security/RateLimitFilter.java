package com.example.TotalSecurity.security;

import java.io.IOException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.FilterChainProxy.FilterChainDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;

import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bucket4j;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;



@Component
@Order(1)
public class RateLimitFilter extends OncePerRequestFilter {
	

	private final Map<String,Bucket> buckets=new ConcurrentHashMap<>();
	
	
	private Bucket resolveBucket(String key) {
		
		return buckets.computeIfAbsent(key,
				k->Bucket4j.builder().
				addLimit(Bandwidth.
						classic(5, 
								Refill.intervally(5, Duration.ofMinutes(1))
								)
						)
				.build()
				);
	}
	
	public boolean isRateLimitedEndPoint(String path) {
		
	
		return path.startsWith("/api/auth/login")||path.startsWith("/api/auth/register")|| 
				path.startsWith("/api/auth/forgot-password") || path.startsWith("/api/auth/refresh");
	
		
	}
	

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		String path=request.getRequestURI();
		
		if(isRateLimitedEndPoint(path)){
			
			String ip=request.getRemoteAddr();
			
			
			Bucket bucket=resolveBucket(ip);
			
			if(!bucket.tryConsume(1)) {
				response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
				response.setContentType("application/json");
				response.getWriter().write("""
						{
						
						"success":false,
					   "message":"Too many requests. Try again later.",
					   "timestamp":"%s"
						
						}
						""".formatted(LocalDateTime.now()));
				return ;
				
			}
			
			
		}
		
		
		
		
		filterChain.doFilter(request, response);
		
	
	
	
		
		
		
	}

	
}
