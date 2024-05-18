package kz.danekerscode.habrspringsecurity6.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kz.danekerscode.habrspringsecurity6.model.entity.User;
import kz.danekerscode.habrspringsecurity6.model.enums.AuthType;
import kz.danekerscode.habrspringsecurity6.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.io.IOException;
import java.util.Arrays;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    record EmailDetails(String email, Boolean primary, Boolean verified) {
    }

    private final UserRepository userRepository;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final RestClient restClient = RestClient.builder()
            .baseUrl("https://api.github.com/user/emails")
            .build();

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication auth
    ) throws IOException {
        if (auth instanceof OAuth2AuthenticationToken auth2AuthenticationToken) {
            var principal = auth2AuthenticationToken.getPrincipal();
            var username = principal.getName();
            var email = fetchUserEmailFromGitHubApi(auth2AuthenticationToken.getAuthorizedClientRegistrationId(), username);

            if (!userRepository.existsByEmail(email)) {
                var user = new User();
                user.setEmail(email);
                user.setAuthType(AuthType.OAUTH2);
                user.setUsername(username);
                userRepository.save(user);
            }
        }

        super.clearAuthenticationAttributes(request);
        super.getRedirectStrategy().sendRedirect(request, response, "/api/v1/auth/me");
    }

    private String fetchUserEmailFromGitHubApi(String clientRegistrationId, String principalName) {
        var authorizedClient = authorizedClientService.loadAuthorizedClient(clientRegistrationId, principalName);
        var accessToken = authorizedClient.getAccessToken().getTokenValue();

        var userEmailsResponse = restClient.get()
                .headers(headers -> headers.setBearerAuth(accessToken))
                .retrieve()
                .body(EmailDetails[].class);

        if (userEmailsResponse == null) {
            return "null";
        }

        var fetchedEmailDetails = Arrays.stream(userEmailsResponse)
                .filter(emailDetails -> emailDetails.verified() && emailDetails.primary())
                .findFirst()
                .orElseGet(() -> null);

        return fetchedEmailDetails != null ? fetchedEmailDetails.email() : "null";
    }

}