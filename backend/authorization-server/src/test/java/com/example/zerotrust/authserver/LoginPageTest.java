package com.example.zerotrust.authserver;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The authorization_code flow redirects an unauthenticated user to
 * /oauth2/login. Spring generates no page when loginPage() is set, so this page
 * is the AS's own and must exist, carry a CSRF token, and run no script.
 */
@SpringBootTest
@AutoConfigureMockMvc
class LoginPageTest {

    @Autowired MockMvc mvc;

    @Test
    void loginPageExistsAndCarriesACsrfToken() throws Exception {
        mvc.perform(get("/oauth2/login").accept("text/html"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("name=\"_csrf\"")))
                .andExpect(content().string(containsString("name=\"username\"")))
                .andExpect(content().string(containsString("type=\"password\"")))
                .andExpect(header().string("Cache-Control", "no-store"));
    }

    @Test
    void loginPageOffersTheCodeFieldWhetherOrNotTheAccountHasTwoStep() throws Exception {
        // Always present, so the page does not reveal which accounts have a second factor.
        mvc.perform(get("/oauth2/login").accept("text/html"))
                .andExpect(content().string(containsString("name=\"otp\"")))
                .andExpect(content().string(containsString("autocomplete=\"one-time-code\"")));
    }

    @Test
    void loginPageAllowsNoScript() throws Exception {
        mvc.perform(get("/oauth2/login").accept("text/html"))
                .andExpect(header().string("Content-Security-Policy", containsString("default-src 'none'")))
                .andExpect(header().string("Content-Security-Policy", not(containsString("script-src"))))
                .andExpect(content().string(not(containsString("<script"))));
    }

    @Test
    void failureMessageDoesNotSayWhichPartWasWrong() throws Exception {
        mvc.perform(get("/oauth2/login").param("error", "").accept("text/html"))
                .andExpect(content().string(containsString("Check your details and try again.")));
    }
}
