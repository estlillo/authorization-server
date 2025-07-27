package com.barbatosdev.authorizationserver.dto;

import java.util.List;

public record UpdateClientRequest(
        String clientName,
        List<String> redirectUris,
        List<String> postLogoutRedirectUris,
        List<String> scopes,
        long accessTokenMinutes,
        long refreshTokenHours,
        boolean reuseRefreshTokens
) {}