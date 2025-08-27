package com.span.learner.uaa;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

import java.time.Clock;

@AutoConfiguration
@EnableConfigurationProperties(UaaTokenProps.class)
public class UaaTokenAutoConfiguration {

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Bean
    public UaaTokenService uaaTokenService(UaaTokenProps props, RestTemplate restTemplate) {
        return new UaaTokenService(props, restTemplate);
    }
}