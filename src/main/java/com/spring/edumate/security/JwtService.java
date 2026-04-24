package com.spring.edumate.security;


import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Service
public class JwtService {
    @Value("${jwt.secret}")
    String secret;

    @Value("${jwt.access-expiration}")
    long accessExp;

    @Value("${jwt.refresh-expiration}")
    long refreshExp;

    SecretKey key() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String accessToken(UserDetails u) {
        return Jwts.builder()
                .setSubject(u.getUsername())
                .setExpiration(new Date(System.currentTimeMillis() + accessExp))
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String refreshToken(UserDetails u) {
        return Jwts.builder()
                .setSubject(u.getUsername())
                .setExpiration(new Date(System.currentTimeMillis() + refreshExp))
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String getUser(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
}