package com.span.learner.uaa;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.Base64;
import java.util.Map;

public class UaaTokenService {

    private final UaaTokenProps props;
    private final RestTemplate restTemplate;
    private volatile CachedToken cached;

    private record CachedToken(String token, Instant expiry) {
    }

    public UaaTokenService(UaaTokenProps props, RestTemplate restTemplate) {
        if (props == null) {
            throw new IllegalArgumentException("UaaTokenProps must not be null. " +
                    "Please configure 'uaa.token' properties in application.yml or application.properties.");
        }
        if (props.clientId() == null || props.clientId().isBlank()) {
            throw new IllegalArgumentException("uaa.token.clientId is required");
        }
        if (props.clientSecret() == null || props.clientSecret().isBlank()) {
            throw new IllegalArgumentException("uaa.token.clientSecret is required");
        }
        if (props.url() == null || props.url().isBlank()) {
            throw new IllegalArgumentException("uaa.token.url is required");
        }
        this.props = props;
        this.restTemplate = restTemplate;
    }

    public synchronized String getToken() {
        Instant now = Instant.now();
        if (cached == null || isAboutToExpire(cached.expiry, now)) {
            cached = fetchToken(now);
        }
        return cached.token;
    }

    private boolean isAboutToExpire(Instant expiry, Instant now) {
        return expiry.minus(props.grace()).isBefore(now);
    }

    private CachedToken fetchToken(Instant now) {
//        HttpHeaders headers = new HttpHeaders();
//        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

//        Map<String, String> body = Map.of(
//                "grant_type", "client_credentials",
//                "client_id", props.clientId(),
//                "client_secret", props.clientSecret()
//        );

//        HttpEntity<Map<String, String>> entity = new HttpEntity<>(body, headers);

        // Prepare body
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "client_credentials");
        body.add("client_id", props.clientId());
        body.add("client_secret", props.clientSecret());

// Create HttpEntity
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

// Exchange
        ResponseEntity<UaaTokenResponse> resp = restTemplate.exchange(
                props.url(),
                HttpMethod.POST,
                request,
                UaaTokenResponse.class);

//        ResponseEntity<UaaTokenResponse> resp =
//                restTemplate.exchange(props.url(), HttpMethod.POST, entity, UaaTokenResponse.class);

        UaaTokenResponse tr = resp.getBody();
        if (tr == null || tr.accessToken() == null) {
            throw new IllegalStateException("Failed to fetch token from " + props.url());
        }

        Instant expiry = extractExpiryFromJwt(tr.accessToken());

        return new CachedToken(tr.accessToken(), expiry);
    }

    @SuppressWarnings("unchecked")
    private Instant extractExpiryFromJwt(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length < 2) {
                throw new IllegalArgumentException("Invalid JWT token");
            }

            // Decode payload
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> payload = mapper.readValue(payloadJson, Map.class);

            if (!payload.containsKey("exp")) {
                throw new IllegalStateException("JWT does not contain exp claim");
            }

            long exp = ((Number) payload.get("exp")).longValue();
            return Instant.ofEpochSecond(exp);

        } catch (Exception e) {
            throw new RuntimeException("Failed to parse JWT token expiry", e);
        }
    }
}