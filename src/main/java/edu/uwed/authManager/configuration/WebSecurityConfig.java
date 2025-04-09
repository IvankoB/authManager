package edu.uwed.authManager.configuration;

/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class WebSecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
            .requestMatchers("/hello", "/test-ldap").permitAll() // Доступ к /hello без аутентификации
            .anyRequest().authenticated() // Все остальные запросы требуют аутентификации
            )
            .httpBasic(httpBasic -> httpBasic.realmName("Realm")); // Современный способ с настройкой realm
        return http.build();
    }
}
