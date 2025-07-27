package com.barbatosdev.authorizationserver.controller;

import com.barbatosdev.authorizationserver.dto.ClientDetailDTO;
import com.barbatosdev.authorizationserver.dto.ClientRegistrationRequest;
import com.barbatosdev.authorizationserver.dto.ClientSummaryDTO;
import com.barbatosdev.authorizationserver.dto.UpdateClientRequest;
import com.barbatosdev.authorizationserver.service.ClientService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/clients")
@AllArgsConstructor
public class ClientController {

    private final ClientService clientService;

    @PostMapping
    public ResponseEntity<String> registerClient(@RequestBody ClientRegistrationRequest req) {
        String response = String.valueOf(clientService.registerClient(req));
        return ResponseEntity.ok(response);
    }

    @GetMapping
    public List<ClientSummaryDTO> getAllClients() {
        return clientService.findAllBasic().stream()
                .map(ClientSummaryDTO::from)
                .toList();
    }

    @GetMapping("/{id}")
    public ResponseEntity<ClientDetailDTO> getClientById(@PathVariable String id) {
        RegisteredClient client = clientService.findById(id);
        if (client == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(ClientDetailDTO.from(client));
    }

    @PutMapping("/{clientId}")
    public ResponseEntity<RegisteredClient> updateClient(@PathVariable String clientId,
                                                         @RequestBody UpdateClientRequest request) {
        RegisteredClient updatedClient = clientService.updateClient(clientId, request);
        return ResponseEntity.ok(updatedClient);
    }
}
