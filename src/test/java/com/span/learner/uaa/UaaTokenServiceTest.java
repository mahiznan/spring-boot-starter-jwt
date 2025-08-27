package com.span.learner.uaa;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.*;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UaaTokenServiceTest {

    @Spy
    UaaTokenProps props = new UaaTokenProps("http://localhost:8083/token", "clientId", "clientSecret", null);
    @Mock
    private RestTemplate restTemplate = new RestTemplate();
    @InjectMocks
    private UaaTokenService service;

    private static String createJwtWithExp(long expEpochSeconds) {
        String headerJson = """
                {
                "alg": "RS256",
                "typ": "JWT"
                }
                """;
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));

        String payloadJson = """
                {
                  "scope": ["openid"],
                  "authorities": ["ROLE_USER"],
                  "jti": "Tdasged-Lsdfij32sdfjsdry8bsd",
                  "client_id": "rajesh",
                  "exp": %d
                }
                """.formatted(expEpochSeconds);

        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));

        return header + "." + payload + ".";
    }

    @Test
    void testFirstFetchStoresToken() {
        String jwt = createJwtWithExp(Instant.now().plusSeconds(300).getEpochSecond());
        UaaTokenResponse response = new UaaTokenResponse(jwt, "bearer", 300, "openid", "jti-123");

        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(HttpEntity.class), eq(UaaTokenResponse.class)))
                .thenReturn(new ResponseEntity<>(response, HttpStatus.OK));

        String token = service.getToken();
        assertNotNull(token);
//        assertTrue(token.contains(jwt));
//        verify(restTemplate, times(1)).exchange(anyString(), eq(HttpMethod.POST), any(), eq(UaaTokenResponse.class));
    }

    @Test
    void testReuseCachedToken() {
        String jwt = createJwtWithExp(Instant.now().plusSeconds(300).getEpochSecond());
        UaaTokenResponse response = new UaaTokenResponse(jwt, "bearer", 300, "openid", "jti-123");

        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(HttpEntity.class), eq(UaaTokenResponse.class)))
                .thenReturn(new ResponseEntity<>(response, HttpStatus.OK));

        // First call fetches from UAA
        String token1 = service.getToken();
        // Second call reuses cached
        String token2 = service.getToken();

        assertEquals(token1, token2);
//        verify(restTemplate, times(1)).exchange(anyString(), eq(HttpMethod.POST), any(), eq(UaaTokenResponse.class));
    }

    @Test
    void testTokenRefreshWhenExpired() {
        long pastExp = Instant.now().minusSeconds(60).getEpochSecond();
        long futureExp = Instant.now().plusSeconds(300).getEpochSecond();

        String expiredJwt = createJwtWithExp(pastExp);
        String freshJwt = createJwtWithExp(futureExp);

        UaaTokenResponse expiredResp = new UaaTokenResponse(expiredJwt, "bearer", 1, "openid", "jti-1");
        UaaTokenResponse freshResp = new UaaTokenResponse(freshJwt, "bearer", 300, "openid", "jti-2");

        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(HttpEntity.class), eq(UaaTokenResponse.class)))
                .thenReturn(new ResponseEntity<>(expiredResp, HttpStatus.OK))
                .thenReturn(new ResponseEntity<>(freshResp, HttpStatus.OK));

        String t1 = service.getToken();
        String t2 = service.getToken();

        assertNotEquals(t1, t2); // refreshed
        verify(restTemplate, times(2)).exchange(anyString(), eq(HttpMethod.POST), any(), eq(UaaTokenResponse.class));
    }

    @Test
    void testInvalidJwtThrowsError() {
        UaaTokenResponse badResp = new UaaTokenResponse("not-a-jwt", "bearer", 100, "openid", "jti-err");

        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(HttpEntity.class), eq(UaaTokenResponse.class)))
                .thenReturn(new ResponseEntity<>(badResp, HttpStatus.OK));

        assertThrows(RuntimeException.class, () -> service.getToken());
    }

    @SuppressWarnings("unchecked")
    @Test
    void testRestTemplateBodyIsCorrect() {
        // Create a fake JWT
        String jwt = createJwtWithExp(Instant.now().plusSeconds(120).getEpochSecond());
        UaaTokenResponse response = new UaaTokenResponse(jwt, "bearer", 120, "openid", "jti-321");

        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(UaaTokenResponse.class)))
                .thenReturn(new ResponseEntity<>(response, HttpStatus.OK));

        service.getToken();

        // Capture HttpEntity
        ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> captor = ArgumentCaptor.forClass((Class) HttpEntity.class);
        verify(restTemplate).exchange(eq("http://localhost:8083/token"), eq(HttpMethod.POST), captor.capture(), eq(UaaTokenResponse.class));

        HttpEntity<MultiValueMap<String, String>> requestEntity = captor.getValue();

        // Verify form body
        MultiValueMap<String, String> body = requestEntity.getBody();
        assertNotNull(body);
        assertEquals("client_credentials", body.getFirst("grant_type"));

        // Verify headers contain Basic Auth
        String authHeader = requestEntity.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        assertNotNull(authHeader);
        assertTrue(authHeader.startsWith("Basic "));

        // Optionally decode Basic Auth and verify clientId and clientSecret
        String base64Creds = authHeader.substring(6);
        String decoded = new String(Base64.getDecoder().decode(base64Creds), StandardCharsets.UTF_8);
        assertEquals("clientId:clientSecret", decoded);
    }
}