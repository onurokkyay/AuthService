package com.krawenn.auth.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.net.URI;
import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class BreachedPasswordsTest {

    // SHA-1 of "password1" is E38AD214943DAAD1D64C102FAEC29DE4AFE9DA3D.
    private static final String PREFIX = "E38AD";
    private static final String SUFFIX = "214943DAAD1D64C102FAEC29DE4AFE9DA3D";

    private MockRestServiceServer pwned;
    private BreachedPasswords breached;

    @BeforeEach
    void setUp() {
        RestClient.Builder http = RestClient.builder();
        pwned = MockRestServiceServer.bindTo(http).build();
        breached = new BreachedPasswords(
                new BreachCheckProperties(true, URI.create("https://pwned.test/"), Duration.ofSeconds(1)),
                http.build());
    }

    @Test
    void onlyTheFirstFiveCharactersOfTheHashLeaveAndAKnownPasswordIsFound() {
        pwned.expect(requestTo("https://pwned.test/range/" + PREFIX))
                .andExpect(header("Add-Padding", "true"))
                .andRespond(withSuccess(
                        "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n" + SUFFIX + ":2413945\r\n", MediaType.TEXT_PLAIN));

        assertThat(breached.isBreached("password1")).isTrue();
        pwned.verify();
    }

    @Test
    void aPaddingLineWithACountOfZeroIsNotABreach() {
        pwned.expect(requestTo("https://pwned.test/range/" + PREFIX))
                .andRespond(withSuccess(SUFFIX + ":0\r\n", MediaType.TEXT_PLAIN));

        assertThat(breached.isBreached("password1")).isFalse();
    }

    @Test
    void whenTheCheckDoesNotAnswerThePasswordIsLetThrough() {
        pwned.expect(requestTo("https://pwned.test/range/" + PREFIX)).andRespond(withServerError());

        assertThat(breached.isBreached("password1")).isFalse();
    }
}
