package kz.danekerscode.habrspringsecurity6.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kz.danekerscode.habrspringsecurity6.model.dto.LoginRequest;
import kz.danekerscode.habrspringsecurity6.model.dto.RegistrationRequest;
import kz.danekerscode.habrspringsecurity6.model.entity.User;
import kz.danekerscode.habrspringsecurity6.model.enums.AuthType;
import kz.danekerscode.habrspringsecurity6.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthService {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;

    public void register(RegistrationRequest request) {
        if (userRepository.existsByEmailAndAuthType(request.email(), AuthType.MANUAL)) {
            throw new IllegalArgumentException("Email already registered");
        }

        var user = new User();
        user.setAuthType(AuthType.MANUAL);
        user.setUsername(request.username());
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));
        userRepository.save(user);
    }

    public Authentication login(
            LoginRequest loginRequest,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        var passwordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                loginRequest.email(), loginRequest.password()
        );

        var auth = authenticationManager.authenticate(passwordAuthenticationToken);
        var securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(auth);
        securityContextRepository.saveContext(securityContext, request, response);

        log.info("Authenticated and created session for {}", auth.getName());
        return auth;
    }

}
