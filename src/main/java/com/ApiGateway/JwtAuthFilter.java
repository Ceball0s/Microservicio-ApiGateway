package com.ApiGateway;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.Key;

@Component
public class JwtAuthFilter implements GlobalFilter, Ordered {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthFilter.class);

    @Value("${JWT_SECRET_KEY}")
    private String secretKey;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        String path = exchange.getRequest().getPath().value();

        logger.info("JWT Filter - Path: {}, Auth Header: {}", path, authHeader != null ? "Present" : "Missing");

        // Permitir endpoints públicos sin token obligatorio
        if (path.startsWith("/api/auth/") || 
            path.startsWith("/api/subasta/") || 
            path.startsWith("/api/ofertas/") || 
            path.startsWith("/api/pedidos/") || 
            path.startsWith("/api/chat/")) {
            logger.info("JWT Filter - Allowing public endpoint without authentication: {}", path);
            return chain.filter(exchange);
        }

        // Comentado: Permitir endpoints de prueba sin autenticación
        // if (path.startsWith("/api/test/")) {
        //     logger.info("JWT Filter - Allowing test endpoint without authentication: {}", path);
        //     return chain.filter(exchange);
        // }

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            try {
                logger.info("JWT Filter - Processing token for path: {}", path);
                
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(getSignInKey())
                        .build()
                        .parseClaimsJws(token)
                        .getBody();

                String userId = claims.getSubject(); // El "sub" debe ser el ID de usuario
                logger.info("JWT Filter - Token validated successfully. User ID: {}, Path: {}", userId, path);

                ServerHttpRequest mutatedRequest = exchange.getRequest()
                        .mutate()
                        .header("user-id", userId)
                        .build();

                return chain.filter(exchange.mutate().request(mutatedRequest).build());
            } catch (Exception e) {
                logger.error("JWT Filter - Token validation failed for path: {}. Error: {}", path, e.getMessage());
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
        }

        // Si no hay token, rechazar la petición
        logger.warn("JWT Filter - No token provided for path: {}, rejecting request", path);
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        return exchange.getResponse().setComplete();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    @Override
    public int getOrder() {
        return -1; // Alta prioridad
    }
}
