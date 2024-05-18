package kz.danekerscode.habrspringsecurity6.model.dto;

public record RegistrationRequest(
        String email,
        String password,
        String username
) {
}
