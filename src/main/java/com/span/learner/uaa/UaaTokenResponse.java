package com.span.learner.uaa;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

public record UaaTokenResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("token_type") String tokenType,
        @JsonProperty("expires_in") long expiresIn,
        @JsonProperty("scope") String scope,   // usually "openid"
        @JsonProperty("jti") String jti,
        Instant expiryTime
) {
    public UaaTokenResponse(String accessToken,
                            String tokenType,
                            long expiresIn,
                            String scope,
                            String jti) {
        this(accessToken, tokenType, expiresIn, scope, jti, null);
    }

    public UaaTokenResponse withExpiryTime(Instant expiryTime) {
        return new UaaTokenResponse(this.accessToken, this.tokenType, this.expiresIn, this.scope, this.jti, expiryTime);
    }
}