package com.spring.edumate.repository;



import com.spring.edumate.entity.BlackToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BlackTokenRepository extends JpaRepository<BlackToken, Long> {
    boolean existsByToken(String token);
}