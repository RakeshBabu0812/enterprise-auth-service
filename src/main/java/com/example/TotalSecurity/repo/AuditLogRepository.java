package com.example.TotalSecurity.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.TotalSecurity.entity.AuditLog;

public interface AuditLogRepository extends JpaRepository<AuditLog,Long> {

}
