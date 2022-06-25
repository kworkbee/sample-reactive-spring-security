package me.g1tommy.reactivesecurity.controller;

import me.g1tommy.reactivesecurity.domain.dto.UserCredentialDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest
@AutoConfigureWebTestClient
class AuthControllerTest {

    @Autowired
    WebTestClient webClient;

    @Test
    @DisplayName("로그인하지 않은 상태에서 서비스 접속 - 401")
    void givenNone_whenLogin_thenUnauthorized() {
        webClient
                .get()
                .uri("/auth/check")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    @DisplayName("로그인 - 200")
    void givenCredential_whenAuthorized_thenExpectedOK() {
        webClient
                .post()
                .uri("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new UserCredentialDto("admin", "admin"))
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    @DisplayName("로그아웃 후 서비스 접속 - 401")
    void givenSession_whenLogoutAndAccessService_thenUnauthorized() {
        givenCredential_whenAuthorized_thenExpectedOK();

        webClient
                .post()
                .uri("/auth/logout")
                .exchange()
                .expectStatus().isOk();

        givenNone_whenLogin_thenUnauthorized();
    }
}