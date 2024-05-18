package kz.danekerscode.habrspringsecurity6.model.dto;

public record LoginRequest(
        String email,
        String password
) {
}
