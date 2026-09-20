package com.example.zerotrust.authserver;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * CORS is allow-list driven: a preflight from a configured origin is approved,
 * and an unconfigured origin gets no Access-Control-Allow-Origin header.
 */
@SpringBootTest(properties = "app.cors.allowed-origins=https://console.example.com")
@AutoConfigureMockMvc
class CorsConfigTest {

    @Autowired MockMvc mockMvc;

    @Test
    void preflightFromAllowedOriginIsApproved() throws Exception {
        mockMvc.perform(options("/api/auth/login")
                        .header("Origin", "https://console.example.com")
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "https://console.example.com"));
    }

    @Test
    void preflightFromUnknownOriginIsNotApproved() throws Exception {
        mockMvc.perform(options("/api/auth/login")
                        .header("Origin", "https://evil.example.com")
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }
}
