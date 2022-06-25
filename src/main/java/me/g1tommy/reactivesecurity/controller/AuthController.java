package me.g1tommy.reactivesecurity.controller;

import lombok.RequiredArgsConstructor;
import me.g1tommy.reactivesecurity.domain.dto.UserCredentialDto;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

import java.util.Optional;

import static org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository.DEFAULT_SPRING_SECURITY_CONTEXT_ATTR_NAME;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private static final String MESSAGE_OK = "ok";
    private static final String MESSAGE_NO_AUTHENTICATION_FOUND = "No Authentication Found";

    private final ReactiveAuthenticationManager authenticationManager;

    @GetMapping("/check")
    public Mono<ResponseEntity<?>> check() {
        return getWebSession()
                .map(session -> {
                    var user = Optional.ofNullable(
                            session.getAttributes().get(DEFAULT_SPRING_SECURITY_CONTEXT_ATTR_NAME)
                    );

                    if (user.isEmpty()) {
                        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(MESSAGE_NO_AUTHENTICATION_FOUND);
                    }

                    return ResponseEntity.ok(MESSAGE_OK);
                });
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<?>> login(@RequestBody UserCredentialDto credential) {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                credential.id(),
                credential.password()
        );

        return authenticationManager.authenticate(token)
                .flatMap(authentication -> getSecurityContext()
                        .flatMap(context -> getWebSession()
                                .map(session -> {
                                    context.setAuthentication(authentication);
                                    session.getAttributes().put(DEFAULT_SPRING_SECURITY_CONTEXT_ATTR_NAME, context);
                                    return ResponseEntity.ok(MESSAGE_OK);
                                })));
    }

    @PostMapping("/logout")
    public Mono<ResponseEntity<?>> logout() {
        return getSecurityContext()
                .flatMap(context -> getWebSession()
                        .map(session -> {
                            context.setAuthentication(null);
                            session.getAttributes().remove(DEFAULT_SPRING_SECURITY_CONTEXT_ATTR_NAME);
                            return ResponseEntity.ok(MESSAGE_OK);
                        }));
    }

    private Mono<ServerWebExchange> getServerWebExchange() {
        return Mono.deferContextual(Mono::just)
                .map(context -> context.get(ServerWebExchange.class));
    }
    
    private Mono<WebSession> getWebSession() {
        return getServerWebExchange()
                .flatMap(ServerWebExchange::getSession);
    }
    
    private Mono<SecurityContext> getSecurityContext() {
        return getWebSession()
                .flatMap(session -> ReactiveSecurityContextHolder.getContext()
                        .switchIfEmpty(Mono.fromSupplier(() -> {
                            var context = new SecurityContextImpl();
                            session.getAttributes().put(DEFAULT_SPRING_SECURITY_CONTEXT_ATTR_NAME, context);
                            return context;
                        })));
    }
}
