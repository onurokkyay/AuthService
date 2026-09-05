package com.krawenn.auth.config;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration(proxyBeanMethods = false)
@EnableScheduling
public class ApplicationConfig {

    /**
     * Token lifetimes and lockout windows are all computed from this bean, so tests can
     * move time instead of sleeping.
     */
    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    /**
     * Strength 12 rather than the default 10: this is the one place where deliberate
     * slowness is the feature, and the cost is paid once per login.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
