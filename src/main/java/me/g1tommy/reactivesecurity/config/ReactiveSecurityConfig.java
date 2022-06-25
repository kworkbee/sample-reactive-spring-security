package me.g1tommy.reactivesecurity.config;

import me.g1tommy.reactivesecurity.domain.dto.RoleType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyUtils;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.session.data.redis.config.annotation.web.server.EnableRedisWebSession;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@EnableRedisWebSession(maxInactiveIntervalInSeconds = 60 * 60 * 2)
public class ReactiveSecurityConfig {

    private static final String MATCHER_ALL_PATH = "/**";
    private static final String MATCHER_AUTH_ALL = "/auth/**";

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf().disable()
                .headers().frameOptions().disable().and()
                .authorizeExchange()
                .pathMatchers(HttpMethod.OPTIONS, MATCHER_ALL_PATH).permitAll()
                .pathMatchers(MATCHER_AUTH_ALL).permitAll()
                .anyExchange().authenticated().and()
                .exceptionHandling().authenticationEntryPoint(new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED)).and()
                .httpBasic().disable()
                .formLogin().disable()
                .logout()
                .logoutSuccessHandler(this::onLogoutSuccess)
                .and()
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public ReactiveAuthenticationManager authenticationManager(
            ReactiveUserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder
    ) {
        var authenticationManager = new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
        authenticationManager.setPasswordEncoder(passwordEncoder);

        return authenticationManager;
    }

    @Bean
    public ReactiveUserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        return new MapReactiveUserDetailsService(
                sampleUser(passwordEncoder, "admin", "ADMIN", "USER"),
                sampleUser(passwordEncoder, "user", "USER")
        );
    }

    @Bean
    public ServerSecurityContextRepository securityContextRepository() {
        return new WebSessionServerSecurityContextRepository();
    }


//    @Bean
//    public WebSessionIdResolver webSessionIdResolver() {
//        HeaderWebSessionIdResolver sessionIdResolver = new HeaderWebSessionIdResolver();
//        sessionIdResolver.setHeaderName("X-AUTH-TOKEN");
//
//        return sessionIdResolver;
//    }
    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy(getRoleHierarchy());

        return roleHierarchy;
    }

    private String getRoleHierarchy() {
        Map<String, List<String>> roleHierarchyMap = new HashMap<>();
        roleHierarchyMap.put(RoleType.ROLE_ADMIN.name(), List.of(RoleType.ROLE_USER.name()));

        return RoleHierarchyUtils.roleHierarchyFromMap(roleHierarchyMap);
    }

    private UserDetails sampleUser(
            PasswordEncoder passwordEncoder,
            String persona,
            String ...roles
    ) {
        return User.builder()
                .username(persona)
                .password(passwordEncoder.encode(persona))
                .roles(roles)
                .build();
    }

    private Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
        return Mono.fromRunnable(() -> exchange.getExchange().getResponse().setStatusCode(HttpStatus.OK));
    }
}
