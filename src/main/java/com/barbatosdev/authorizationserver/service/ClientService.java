package com.barbatosdev.authorizationserver.service;

import com.barbatosdev.authorizationserver.dto.ClientRegistrationRequest;
import com.barbatosdev.authorizationserver.dto.UpdateClientRequest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.List;

public interface ClientService {
    String registerClient(ClientRegistrationRequest req);

    List<RegisteredClient> findAllBasic();

    RegisteredClient findById(String id);

    RegisteredClient updateClient(String id, UpdateClientRequest request);
}
