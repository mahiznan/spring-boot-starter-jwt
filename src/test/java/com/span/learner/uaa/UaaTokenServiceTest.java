package com.span.learner.uaa;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UaaTokenServiceTest {

//    @Spy
    UaaTokenProps props = new UaaTokenProps("http://localhost:8083/token", "clientId", "clientSecret", null);
//    @Mock
    private RestTemplate restTemplate = new RestTemplate();
//    @InjectMocks
    private UaaTokenService service = new UaaTokenService(props, restTemplate);

    private static String createJwtWithExp(long expEpochSeconds) {
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));

        String payloadJson = String.format("{\"exp\":%d,\"scope\":[\"openid\"],\"client_id\":\"rajesh\"}", expEpochSeconds);
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));

        return header + "." + payload + ".";
    }

    @Test
    void testFirstFetchStoresToken() {
        String jwt = createJwtWithExp(Instant.now().plusSeconds(300).getEpochSecond());
        UaaTokenResponse response = new UaaTokenResponse(jwt, "bearer", 300, "openid", "jti-123");

//        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(HttpEntity.class), eq(UaaTokenResponse.class)))
//                .thenReturn(new ResponseEntity<>(response, HttpStatus.OK));

        String token = service.getToken();
        assertNotNull(token);
//        assertTrue(token.contains(jwt));
//        verify(restTemplate, times(1)).exchange(anyString(), eq(HttpMethod.POST), any(), eq(UaaTokenResponse.class));
    }

    @Test
    void testReuseCachedToken() {
        String jwt = createJwtWithExp(Instant.now().plusSeconds(300).getEpochSecond());
        UaaTokenResponse response = new UaaTokenResponse(jwt, "bearer", 300, "openid", "jti-123");

//        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(HttpEntity.class), eq(UaaTokenResponse.class)))
//                .thenReturn(new ResponseEntity<>(response, HttpStatus.OK));

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
        String jwt = createJwtWithExp(Instant.now().plusSeconds(120).getEpochSecond());
        UaaTokenResponse response = new UaaTokenResponse(jwt, "bearer", 120, "openid", "jti-321");

        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(HttpEntity.class), eq(UaaTokenResponse.class)))
                .thenReturn(new ResponseEntity<>(response, HttpStatus.OK));

        service.getToken();

        ArgumentCaptor<HttpEntity<Map<String, String>>> captor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(restTemplate).exchange(eq("http://uaa/token"), eq(HttpMethod.POST), captor.capture(), eq(UaaTokenResponse.class));

        Map<String, String> body = captor.getValue().getBody();
        assertEquals("clientId", body.get("client_id"));
        assertEquals("clientSecret", body.get("client_secret"));
        assertEquals("client_credentials", body.get("grant_type"));
    }
}