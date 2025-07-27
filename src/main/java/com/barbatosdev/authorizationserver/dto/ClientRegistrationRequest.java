package com.barbatosdev.authorizationserver.dto;

import java.util.List;

public record ClientRegistrationRequest(
        String clientId,
        String clientSecret,
        String clientName,
        List<String> redirectUris,
        List<String> postLogoutRedirectUris,
        List<String> scopes,
        boolean publicClient
) {}
