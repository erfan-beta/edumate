package com.spring.edumate.controller;



import com.spring.edumate.dto.AuthResponse;
import com.spring.edumate.dto.LoginRequest;
import com.spring.edumate.dto.RegisterRequest;
import com.spring.edumate.service.AuthService;
import com.spring.edumate.repository.BlackTokenRepository;
import com.spring.edumate.entity.BlackToken;
import com.spring.edumate.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class AuthController {
    private final AuthService service;
    private final BlackTokenRepository blackRepo;
    private final JwtService jwt;

    @PostMapping("/register")
    public AuthResponse register(@RequestBody RegisterRequest r) {
        return service.register(r);
    }

    @PostMapping("/login")
    public AuthResponse login(@RequestBody LoginRequest r) {
        return service.login(r);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestHeader("Authorization") String h,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        // Security Fix: Check header length
        if (h != null && h.startsWith("Bearer ") && h.length() > 7) {
            String token = h.substring(7);
            // Security Fix: Idempotent (ignore if already exists)
            if (!blackRepo.existsByToken(token)) {
                blackRepo.save(new BlackToken(null, token));
            }
        }
        // Security Fix: Revoke refresh tokens
        if (userDetails != null) {
            service.logout(userDetails.getUsername());
        }
        return ResponseEntity.ok().build();
    }

    @GetMapping("/test/student")
    public ResponseEntity<String> studentEndpoint() {
        return ResponseEntity.ok("Student access granted");
    }

    @GetMapping("/test/instructor")
    public ResponseEntity<String> instructorEndpoint() {
        return ResponseEntity.ok("Instructor access granted");
    }

    @GetMapping("/test/admin")
    public ResponseEntity<String> adminEndpoint() {
        return ResponseEntity.ok("Admin access granted");
    }
}