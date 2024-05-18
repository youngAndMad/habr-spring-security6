package kz.danekerscode.habrspringsecurity6.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kz.danekerscode.habrspringsecurity6.model.dto.LoginRequest;
import kz.danekerscode.habrspringsecurity6.model.dto.RegistrationRequest;
import kz.danekerscode.habrspringsecurity6.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RequiredArgsConstructor
@RestController
@RequestMapping("api/v1/auth")
public class AuthController {

    private final AuthService authService;

    @GetMapping("me")
    Principal me(Principal principal) {
        return principal;
    }

    @PostMapping("register")
    @ResponseStatus(HttpStatus.CREATED)
    void register(@RequestBody RegistrationRequest request) {
        authService.register(request);
    }

    @PostMapping("login")
    Object login(
            @RequestBody LoginRequest loginRequest,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        return authService
                .login(loginRequest, request, response)
                .getPrincipal();
    }

}
