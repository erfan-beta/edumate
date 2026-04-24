package com.spring.edumate.service;


import com.spring.edumate.dto.AuthResponse;
import com.spring.edumate.dto.LoginRequest;
import com.spring.edumate.dto.RegisterRequest;
import com.spring.edumate.dto.UserDto;
import com.spring.edumate.entity.Role;
import com.spring.edumate.entity.User;
import com.spring.edumate.entity.RefreshToken;
import com.spring.edumate.repository.UserRepository;
import com.spring.edumate.repository.RoleRepository;
import com.spring.edumate.repository.RefreshTokenRepository;
import com.spring.edumate.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepo;
    private final RoleRepository roleRepo;
    private final RefreshTokenRepository refreshRepo;
    private final PasswordEncoder encoder;
    private final JwtService jwt;
    private final AuthenticationManager manager;

    @Transactional
    public AuthResponse register(RegisterRequest r) {
        if (userRepo.existsByEmail(r.getEmail()))
            throw new RuntimeException("Email already registered");

        Role role = roleRepo.findByName("STUDENT").orElseThrow();

        User u = User.builder()
                .email(r.getEmail().toLowerCase().trim())
                .password(encoder.encode(r.getPassword()))
                .firstName(r.getFirstName())
                .lastName(r.getLastName())
                .isActive(true)
                .isVerified(true)
                .roles(Set.of(role))
                .build();

        userRepo.save(u);
        return login(new LoginRequest(r.getEmail(), r.getPassword()));
    }

    public AuthResponse login(LoginRequest r) {
        manager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        r.getEmail().toLowerCase().trim(),
                        r.getPassword()
                )
        );

        User u = userRepo.findByEmail(r.getEmail().toLowerCase().trim()).orElseThrow();
        u.setLastLoginAt(LocalDateTime.now());
        userRepo.save(u);

        UserDetails ud = org.springframework.security.core.userdetails.User.builder()
                .username(u.getEmail())
                .password(u.getPassword())
                .authorities(
                        String.valueOf(u.getRoles().stream()
                               .map(x -> "ROLE_" + x.getName())
                               .collect(Collectors.toList()))
                )
                .build();

        String access = jwt.accessToken(ud);
        String refresh = jwt.refreshToken(ud);

        refreshRepo.save(
                RefreshToken.builder()
                        .token(refresh)
                        .email(u.getEmail())
                        .expiry(LocalDateTime.now().plusDays(7))
                        .build()
        );

        return AuthResponse.builder()
                .accessToken(access)
                .refreshToken(refresh)
                .expiresAt(LocalDateTime.now().plusMinutes(15))
                .user(toDto(u))
                .build();
    }

    public void logout(String email) {
        // Security Fix: Revoke all refresh tokens for this user
        refreshRepo.deleteByEmail(email);
    }

    private UserDto toDto(User u) {
        return UserDto.builder()
                .id(u.getId())
                .email(u.getEmail())
                .firstName(u.getFirstName())
                .lastName(u.getLastName())
                .roles(u.getRoles().stream().map(Role::getName).collect(Collectors.toSet()))
                .build();
    }
}