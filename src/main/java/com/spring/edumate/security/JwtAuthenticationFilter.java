package com.spring.edumate.security;



import com.spring.edumate.repository.BlackTokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwt;
    private final UserDetailsService uds;
    private final BlackTokenRepository blackRepo;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest req,
            @NonNull HttpServletResponse res,
            @NonNull FilterChain chain
    ) throws IOException, ServletException {
        String h = req.getHeader("Authorization");

        // Security Fix: Check header length before substring
        if (h != null && h.startsWith("Bearer ") && h.length() > 7) {
            String token = h.substring(7);

            if (blackRepo.existsByToken(token)) {
                chain.doFilter(req, res);
                return;
            }

            String email = jwt.getUser(token);
            if (StringUtils.hasText(email)) {
                UserDetails u = uds.loadUserByUsername(email);
                UsernamePasswordAuthenticationToken a =
                        new UsernamePasswordAuthenticationToken(u, null, u.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(a);
            }
        }
        chain.doFilter(req, res);
    }
}