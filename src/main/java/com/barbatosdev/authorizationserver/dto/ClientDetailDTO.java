package com.barbatosdev.authorizationserver.dto;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.util.Set;
import java.util.stream.Collectors;

public record ClientDetailDTO(
        String id,
        String clientId,
        String clientName,
        Set<String> authenticationMethods,
        Set<String> grantTypes,
        Set<String> redirectUris,
        Set<String> postLogoutRedirectUris,
        Set<String> scopes,
        ClientSettings clientSettings,
        TokenSettings tokenSettings
) {
    public static ClientDetailDTO from(RegisteredClient client) {
        return new ClientDetailDTO(
                client.getId(),
                client.getClientId(),
                client.getClientName(),
                client.getClientAuthenticationMethods().stream()
                        .map(ClientAuthenticationMethod::getValue)
                        .collect(Collectors.toSet()),
                client.getAuthorizationGrantTypes().stream()
                        .map(AuthorizationGrantType::getValue)
                        .collect(Collectors.toSet()),
                client.getRedirectUris(),
                client.getPostLogoutRedirectUris(),
                client.getScopes(),
                client.getClientSettings(),
                client.getTokenSettings()
        );
    }
}
