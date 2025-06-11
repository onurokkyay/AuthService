package com.krawenn.auth.config;

import com.krawenn.auth.service.AuthService;
import org.mockito.Mockito;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

@TestConfiguration
public class MockAuthServiceTestConfig {

    @Bean
    public AuthService authService() {
        return Mockito.mock(AuthService.class);
    }
}