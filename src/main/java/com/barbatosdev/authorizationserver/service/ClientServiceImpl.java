package com.barbatosdev.authorizationserver.service;

import com.barbatosdev.authorizationserver.dto.ClientRegistrationRequest;
import com.barbatosdev.authorizationserver.dto.UpdateClientRequest;
import lombok.AllArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Service
@AllArgsConstructor
public class ClientServiceImpl implements ClientService {

    private final JdbcTemplate jdbcTemplate;
    private final RegisteredClientRepository jdbcRepo;

    @Override
    @Transactional
    public String registerClient(ClientRegistrationRequest req) {
        // Si ya existe
        if (jdbcRepo.findByClientId(req.clientId()) != null) {
            throw new RuntimeException("Client with this id already exists");
        }

        // Construir RegisteredClient
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(req.clientId())
                .clientName(req.clientName())
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE);

        if (!req.publicClient()) {
            builder.clientSecret("{noop}" + req.clientSecret())
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        } else {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
        }

        // Grant types básicos
        builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);

        // URIs
        req.redirectUris().forEach(builder::redirectUri);
        req.postLogoutRedirectUris().forEach(builder::postLogoutRedirectUri);

        // Scopes
        req.scopes().forEach(builder::scope);

        // PKCE obligatorio si es público
        builder.clientSettings(ClientSettings.builder()
                .requireProofKey(req.publicClient()) // PKCE solo si es público
                .requireAuthorizationConsent(true)
                .build());

        // Token settings
        builder.tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(30))
                .refreshTokenTimeToLive(Duration.ofDays(30))
                .reuseRefreshTokens(true)
                .build());

        // Registrar en BD
        jdbcRepo.save(builder.build());

        return "Client registered";
    }

    @Override
    public List<RegisteredClient> findAllBasic() {
        List<String> ids = jdbcTemplate.queryForList(
                "SELECT id FROM oauth2_registered_client", String.class);
        return ids.stream()
                .map(jdbcRepo::findById)
                .filter(Objects::nonNull)
                .toList();
    }

    @Override
    public RegisteredClient findById(String id) {
        return jdbcRepo.findById(id);
    }

    @Override
    @Transactional
    public RegisteredClient updateClient(String id, UpdateClientRequest request) {
        RegisteredClient existingClient = jdbcRepo.findById(id);
        if (existingClient == null) {
            throw new RuntimeException("Client not found");
        }

        RegisteredClient updatedClient = RegisteredClient.from(existingClient)
                .clientName(request.clientName())
                .redirectUris(uris -> {
                    uris.clear();
                    uris.addAll(request.redirectUris());
                })
                .postLogoutRedirectUris(uris -> {
                    uris.clear();
                    uris.addAll(request.postLogoutRedirectUris());
                })
                .scopes(scopes -> {
                    scopes.clear();
                    scopes.addAll(request.scopes());
                })
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(request.accessTokenMinutes()))
                        .refreshTokenTimeToLive(Duration.ofHours(request.refreshTokenHours()))
                        .reuseRefreshTokens(request.reuseRefreshTokens())
                        .build()
                )
                .build();

        jdbcRepo.save(updatedClient);

        return updatedClient;
    }
}
