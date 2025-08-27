package com.span.learner.uaa;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "uaa.token")
public record UaaTokenProps(
        String url,
        String clientId,
        String clientSecret,
        Duration grace
) {
    public UaaTokenProps(String url, String clientId, String clientSecret, Duration grace) {
        this.url = url;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.grace = grace == null ? Duration.ofSeconds(60) : grace;
    }
}