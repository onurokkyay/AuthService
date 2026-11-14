package com.krawenn.auth.account;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

import com.krawenn.auth.TestAuthProperties;
import com.krawenn.auth.config.AuthProperties;
import com.krawenn.auth.error.AccountDeletionIncompleteException;
import com.krawenn.auth.error.InvalidCurrentPasswordException;
import com.krawenn.auth.user.TestUsers;
import com.krawenn.auth.user.User;
import com.krawenn.auth.user.UserRepository;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.web.client.RestClient;

@ExtendWith(MockitoExtension.class)
class AccountDeletionTest {

    private static final String APPLICATION = "http://gateway.test/api/me";
    private static final String TOKEN = "the-callers-access-token";

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private PlatformTransactionManager transactionManager;

    private MockRestServiceServer application;
    private AccountDeletion deletion;
    private UUID userId;
    private User user;

    @BeforeEach
    void setUp() {
        AuthProperties defaults = TestAuthProperties.create();
        AuthProperties properties = new AuthProperties(
                defaults.jwt(),
                defaults.refreshToken(),
                defaults.login(),
                defaults.registration(),
                defaults.cors(),
                defaults.passwordReset(),
                new AuthProperties.AccountDeletion(List.of(URI.create(APPLICATION)), Duration.ofSeconds(5)));
        RestClient.Builder http = RestClient.builder();
        application = MockRestServiceServer.bindTo(http).build();
        deletion = new AccountDeletion(
                userRepository,
                passwordEncoder,
                properties,
                transactionManager,
                Clock.fixed(Instant.parse("2026-11-14T12:00:00Z"), ZoneOffset.UTC),
                http.build());
        userId = UUID.randomUUID();
        user = TestUsers.withId(userId);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
    }

    @Test
    void theApplicationsDeleteFirstWithTheCallersOwnTokenAndOnlyThenTheAccountCloses() {
        when(passwordEncoder.matches("correct horse battery", TestUsers.PASSWORD_HASH))
                .thenReturn(true);
        application
                .expect(requestTo(APPLICATION))
                .andExpect(method(HttpMethod.DELETE))
                .andExpect(header("Authorization", "Bearer " + TOKEN))
                .andRespond(withStatus(HttpStatus.NO_CONTENT));

        deletion.delete(userId, "correct horse battery", TOKEN);

        application.verify();
        verify(userRepository).deleteById(userId);
    }

    @Test
    void anApplicationThatDoesNotConfirmLeavesTheAccountOpen() {
        when(passwordEncoder.matches("correct horse battery", TestUsers.PASSWORD_HASH))
                .thenReturn(true);
        application.expect(requestTo(APPLICATION)).andRespond(withServerError());

        assertThatThrownBy(() -> deletion.delete(userId, "correct horse battery", TOKEN))
                .isInstanceOf(AccountDeletionIncompleteException.class);
        verify(userRepository, never()).deleteById(any());
    }

    @Test
    void aWrongPasswordDeletesNothingAnywhereAndCountsTowardsTheLockout() {
        when(passwordEncoder.matches("guess", TestUsers.PASSWORD_HASH)).thenReturn(false);

        assertThatThrownBy(() -> deletion.delete(userId, "guess", TOKEN))
                .isInstanceOf(InvalidCurrentPasswordException.class);

        application.verify();
        verify(userRepository, never()).deleteById(any());
        assertThat(ReflectionTestUtils.getField(user, "failedLoginAttempts")).isEqualTo(1);
    }
}
