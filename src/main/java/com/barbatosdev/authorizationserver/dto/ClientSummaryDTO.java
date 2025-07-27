package com.barbatosdev.authorizationserver.dto;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.Set;
import java.util.stream.Collectors;

public record ClientSummaryDTO(
        String id,
        String clientId,
        String clientName,
        Set<String> grantTypes,
        Set<String> scopes
) {
    public static ClientSummaryDTO from(RegisteredClient client) {
        return new ClientSummaryDTO(
                client.getId(),
                client.getClientId(),
                client.getClientName(),
                client.getAuthorizationGrantTypes().stream()
                        .map(AuthorizationGrantType::getValue)
                        .collect(Collectors.toSet()),
                client.getScopes()
        );
    }
}
