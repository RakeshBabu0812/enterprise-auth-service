package com.example.TotalSecurity.exception;



import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.example.TotalSecurity.dto.ErrorResponse;



@RestControllerAdvice
public class GlobalExceptionHandler  {
	
	
	
	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<ErrorResponse> validationError(MethodArgumentNotValidException e) {
		
		System.out.println(e.getBindingResult().getAllErrors());
		String message=e.getBindingResult().getFieldErrors().get(0).getDefaultMessage();
		
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorResponse(message));
	
	}
	 @ExceptionHandler(EmailAlreadyExistsException.class)
	    public ResponseEntity<ErrorResponse> handleEmailExists(EmailAlreadyExistsException ex) {

	        return ResponseEntity.status(HttpStatus.CONFLICT).body(new ErrorResponse(ex.getMessage()));
	    }
	 
	 
	 @ExceptionHandler(TooManyRequestException.class)
	 public ResponseEntity<ErrorResponse> handleTooManyRequests(TooManyRequestException ex){
		 
		 
		 return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(new ErrorResponse(ex.getMessage()));
		 
		 
	 }
	
	 
	@ExceptionHandler(RuntimeException.class)
	public ResponseEntity<ErrorResponse> runtimeErrors(RuntimeException e){
		
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorResponse(e.getMessage()));

	}
	
	

	
	
	

}


