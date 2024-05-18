package kz.danekerscode.habrspringsecurity6.config;

import kz.danekerscode.habrspringsecurity6.model.enums.AuthType;
import kz.danekerscode.habrspringsecurity6.repository.UserRepository;
import kz.danekerscode.habrspringsecurity6.security.OAuth2AuthenticationSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final static String[] PUBLIC_ENDPOINTS = {
            "/api/v1/auth/register",
            "/api/v1/auth/login",
            "/oauth2/**",
            "/error"
    };

    @Bean
        // Далее этот бин мы будем использовать для login ендпоинта
    AuthenticationManager authenticationManager(
            HttpSecurity http,
            AuthenticationProvider daoAuthenticationProvider
    )
            throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .authenticationProvider(daoAuthenticationProvider)
                .build();
    }

    @Bean
    SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler
    ) throws Exception {
        final HttpStatusEntryPoint httpStatusEntryPoint = new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);

        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .exceptionHandling(e -> e.authenticationEntryPoint(httpStatusEntryPoint))
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                            .anyRequest().permitAll();
                })
                .oauth2Login(oauth2Login -> {
                    oauth2Login.successHandler(oAuth2AuthenticationSuccessHandler)
                            .permitAll();
                })
                /*
                Если вы отправите POST-запрос на /logout-url-there, то система выполнит следующие операции по умолчанию с использованием ряда LogoutHandlers:
                Аннулирует HTTP-сессию (SecurityContextLogoutHandler)
                Очистит SecurityContextHolderStrategy (SecurityContextLogoutHandler)
                Очистит SecurityContextRepository (SecurityContextLogoutHandler)
                Удалит любую RememberMe аутентификацию (TokenRememberMeServices / PersistentTokenRememberMeServices)
                Удалит сохраненный токен CSRF (CsrfLogoutHandler)
                Вызовет событие LogoutSuccessEvent (LogoutSuccessEventPublishingLogoutHandler)
                После выполнения этих действий, система использует свой стандартный LogoutSuccessHandler, который перенаправляет на /login?logout.
                */
                .logout(logoutSettings -> logoutSettings
                        .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler())
                        .logoutUrl("/api/v1/auth/logout")
                        .permitAll()
                );

        return http.build();
    }

    @Bean
    UserDetailsService userDetailsService(
            UserRepository userRepository
    ) {
        return email -> userRepository.findByEmailAndAuthType(email, AuthType.MANUAL)
                .orElseThrow(() -> new UsernameNotFoundException("User by email %s not found".formatted(email)));
    }

    @Bean
        // Бин для хэширование паролей пользователей
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    AuthenticationProvider daoAuthenticationProvider(
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder
    ) {
        var authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder);
        authenticationProvider.setHideUserNotFoundExceptions(false);
        return authenticationProvider;
    }

    @Bean
// Бин для вручного сохранение сессии в редис
    SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }
}
