# 🔐 Enterprise Authentication & Authorization Service

A production-grade authentication system built using Spring Boot and Spring Security.

This project demonstrates a production-ready authentication and authorization system using JWT, Google OAuth2, rate limiting, account locking, audit logging, and role-based access control, following industry best practices.

---

## 🚀 Key Features

### 🔑 Authentication

- JWT Access Token (short-lived)
- Refresh Token Rotation with reuse detection
- Secure password hashing using BCrypt
- Stateless authentication (no session storage)

### 🔄 Token Security

- Refresh token hashing (SHA-256 + constant-time comparison)
- Refresh token invalidation on:
  - Logout
  - Password change
  - Password reset
- Token invalidation timestamp support

### 📧 Email System

- Email verification after registration
- Verification token expiry handling
- Resend verification with rate limiting
- Secure password reset via email token

### 🛡 Account Protection

- Account locking after 5 failed login attempts
- Temporary lock (15 minutes)
- Failed login tracking
- Audit logging for all security events

### 🌐 Google OAuth2 Login

- Google ID token verification
- Auto-account creation for new Google users
- Identity-based authentication using verified email
- Provider-aware login handling (LOCAL / GOOGLE)
- Prevents duplicate accounts across providers
- Secure mixed authentication support

### 🚦 Rate Limiting (Anti-Brute-Force)

- Login rate limiting
- Registration rate limiting
- Forgot password rate limiting
- Refresh token endpoint protection
- Resend verification rate limiting

### 👥 Role-Based Authorization (RBAC)

- USER and ADMIN roles
- Role hierarchy (ADMIN > USER)
- Endpoint-level authorization rules
- Method-level security using @PreAuthorize

### 📜 Audit Logging

- Login success
- Login failure
- Account locked
- Password changed
- Password reset
- Logout
- Stored securely in database

📘 API Documentation

Swagger (OpenAPI 3)

Bearer token authentication support in Swagger UI

---

## 🛠 Tech Stack

- Java 17
- Spring Boot 3
- Spring Security 6
- JSON Web Tokens (JJWT)
- Google OAuth2
- Bucket4j (Rate Limiting)
- MySQL
- Swagger / OpenAPI
- Maven

---

## 📸 Screenshots

### 1️⃣ Swagger Overview

<img width="900" height="2426" alt="localhost_8080_swagger-ui_index html" src="https://github.com/user-attachments/assets/a6385417-5141-4475-9123-25f61a764cdc" /> 

### 2️⃣ Login – JWT Response

<img width="900" height="501" alt="swagger_login" src="https://github.com/user-attachments/assets/f5f98635-dbb3-4b65-9290-9772a9e54729" />

### 3️⃣ Rate Limiting – 429 Response

<img width="900" height="511" alt="TooManyRequests" src="https://github.com/user-attachments/assets/54df3b91-041d-4df9-addb-bf0ba0e0eec3" />  

### 4️⃣ Role-Based Access – 403 Example

<img width="900" height="462" alt="AccessBased" src="https://github.com/user-attachments/assets/684e14af-24a4-44d1-a899-8c369eb5e3c1" />  

---

## 🌐 Google OAuth2 Integration

This project includes backend support for Google OAuth2 login via the /api/auth/google endpoint.

The endpoint expects a valid Google ID token generated from a frontend application using Google Identity Services.

⚠️ Important:
Since this repository contains only the backend service, a frontend client is required to obtain a valid Google ID token before calling this endpoint.

Example frontend integrations:
- React (Google Identity Services)
- Angular
- Mobile applications (Android / iOS)
- Any OAuth2-compliant client

Without a frontend, the Google login endpoint cannot be fully tested because ID token generation occurs on the client side.


---

## 🔐 Security Highlights

- Stateless architecture
- No refresh tokens stored in plain text
- Constant-time comparison for hashed tokens
- Token rotation strategy
- Account lockout protection
- Email verification required before login
- Identity-based authentication with provider-aware validation (LOCAL / GOOGLE)
- Centralized exception handling
  
---

## ⚙️ How to Clone & Run

### 1️⃣ Clone the Repository

``` bash
git clone https://github.com/RakeshBabu0812/enterprise-auth-service.git  
cd enterprise-auth-service

 ```
### 2️⃣ Configure Environment

This project includes an application-example.properties file
as a reference configuration.

Before running the application:
- Copy or rename it to application.properties
- Configure your database credentials
- Configure your email credentials
- Set your desired server port
  
Sensitive data like passwords should not be committed to version control.

### 3️⃣ Run the Application
``` bash 
mvn spring-boot:run

 ```
or run from your IDE.

### 4️⃣ Open Swagger UI

``` bash 
http://localhost:8080/swagger-ui/index.html
 ```

### 👨‍💻 Author

Rakesh Babu  
Backend Developer specializing in Spring Boot & Security
