# 🚀 Spring Authorization Server + SPA PKCE Demo

Este proyecto implementa un **Authorization Server (OAuth2 + OIDC)** usando **Spring Authorization Server**, con dos tipos de clientes:

1. **Backend privado** con `client_credentials` (API-to-API)
2. **SPA pública** con `authorization_code + PKCE` (sin client_secret)

Incluye un cliente de ejemplo en **React + TypeScript** para probar el flujo PKCE.

---

## 🏗️ Arquitectura del MVP

```
[React SPA] <--PKCE--> [Spring Authorization Server] <--JWT--> [Recursos protegidos]
```

- **Authorization Server**
    - Genera y firma tokens JWT con claves RSA
    - Expone endpoints:
        - `/oauth2/authorize`
        - `/oauth2/token`
        - `/oauth2/jwks`
        - `/oauth2/introspect`
        - `/oauth2/revoke`
        - `.well-known/openid-configuration`
    - Incluye login con `UsernamePasswordAuthenticationFilter` + consent screen

- **React SPA**
    - Genera `code_verifier` y `code_challenge`
    - Redirige al Authorization Server para autenticar y consentir scopes
    - Intercambia el `authorization_code` por `access_token` vía `/oauth2/token`

---

## 🔑 **Clientes registrados**

### ✅ 1. Cliente Backend (privado)

```java
RegisteredClient.withId(UUID.randomUUID().toString())
    .clientId("backend-client")
    .clientSecret("{noop}super-secret")
    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
    .scope("api.read")
```

- **Tipo:** Confidencial
- **Grant Type:** `client_credentials`
- **Uso típico:** API-to-API sin interacción de usuario

---

### ✅ 2. Cliente SPA (público) → PKCE obligatorio

```java
RegisteredClient.withId(UUID.randomUUID().toString())
    .clientId("public-client")
    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
    .redirectUri("http://localhost:4200/callback")
    .redirectUri("http://localhost:4200/callback/")
    .scope(OidcScopes.OPENID)
    .scope(OidcScopes.PROFILE)
    .clientSettings(ClientSettings.builder()
        .requireProofKey(true) // ✅ PKCE obligatorio
        .requireAuthorizationConsent(true) // ✅ Solicitar consentimiento
        .build())
```

- **Tipo:** Público (sin client_secret)
- **Grant Type:** `authorization_code + PKCE`
- **Redirect URI:**
    - `http://localhost:4200/callback`
    - `http://localhost:4200/callback/`
- **Scopes:** `openid profile`

---

## ⚙️ **Configuración del Authorization Server**

### 🔒 Seguridad principal

```java
@Bean
@Order(1)
public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
            OAuth2AuthorizationServerConfigurer.authorizationServer();

    http
        .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
        .with(authorizationServerConfigurer, (authorizationServer) -> authorizationServer
            .oidc(Customizer.withDefaults()) // ✅ OpenID Connect habilitado
        )
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .cors(Customizer.withDefaults()) // ✅ Necesario para SPA
        .csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/token")) // ✅ Ignorar CSRF en token endpoint
        .exceptionHandling(ex -> ex.defaultAuthenticationEntryPointFor(
            new LoginUrlAuthenticationEntryPoint("/login"),
            new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
        ));
    return http.build();
}
```

- **Login web:** `/login`
- **Consent screen** habilitado para PKCE
- **CORS habilitado para `http://localhost:4200`**

---

### 🔐 Generación de claves RSA para firmar JWT

```java
@Bean
public JWKSource<SecurityContext> jwkSource() {
    RSAKey rsaKey = generateRsa();
    return (selector, context) -> selector.select(new JWKSet(rsaKey));
}
```

- **Formato:** JWT *self-contained*
- **JWK Set disponible en:**
  ```
  http://localhost:9000/oauth2/jwks
  ```

---

### 👤 Usuarios de prueba

```java
@Bean
public UserDetailsService userDetailsService() {
    var user = User.withUsername("user")
        .password("{noop}password")
        .roles("USER")
        .build();
    return new InMemoryUserDetailsManager(user);
}
```

- Usuario default: **`user` / `password`**

---

## 🌐 **React SPA con PKCE**

Cliente minimalista en **React + TypeScript**:

- Genera `code_verifier` y `code_challenge`
- Llama al `/oauth2/authorize`
- Recibe `authorization_code` y lo intercambia en `/oauth2/token`

Config:

```ts
export const authConfig = {
  authServer: 'http://localhost:9000',
  clientId: 'public-client',
  redirectUri: 'http://localhost:4200/callback',
  scopes: 'openid profile'
};
```

Flujo:

1. `Login with PKCE` → redirige a `/oauth2/authorize`
2. El Authorization Server pide login y consentimiento
3. Redirige al SPA → `/callback?code=XYZ`
4. El SPA hace `POST /oauth2/token` con `code_verifier`
5. Recibe `access_token` y lo guarda en memoria

---

## 🚀 **Cómo levantar el proyecto**

### ✅ 1. Backend: Authorization Server

```bash
./gradlew bootRun
```

- Corre en `http://localhost:9000`

---

### ✅ 2. Frontend: React SPA

```bash
cd react-spa-pkce
npm install
npm run dev
```

- Corre en `http://localhost:4200`

---

### ✅ 3. Flujo completo

1. Abre `http://localhost:4200`
2. Click en **Login with PKCE**
3. Redirige a `http://localhost:9000/login`
4. Login con **`user` / `password`**
5. Acepta **consent screen**
6. SPA recibe el `access_token`

---

## 🛠️ **Troubleshooting**

✅ Si `/oauth2/token` devuelve **403 Forbidden**:
- Verifica que **CORS permita `http://localhost:4200`**
- Asegúrate de ignorar CSRF en `/oauth2/token`

✅ Si **redirect_uri mismatch**:
- Agrega ambas URIs en `RegisteredClient`: con y sin `/` al final

✅ Si al refrescar sigue logueado:
- Borra cookies de `localhost:9000`

---

## 📖 **Endpoints clave**

- `/oauth2/authorize` → inicio del flujo PKCE
- `/oauth2/token` → intercambio de código por token
- `/oauth2/jwks` → claves públicas para validar JWT
- `/.well-known/openid-configuration` → metadata OIDC
- `/login` → login form básico

---

## 🔮 Próximos pasos

- ✅ Añadir más claims personalizados al `access_token`
- ✅ Configurar persistencia en base de datos para `RegisteredClient` y `OAuth2Authorization`
- ✅ Añadir logout OIDC
- ✅ Integrar un Resource Server que valide los tokens emitidos

---

## 👨‍💻 Autor

**Spring Authorization Server PKCE Demo**  
Hecho con ❤️ por Tu Nombre / Equipo
