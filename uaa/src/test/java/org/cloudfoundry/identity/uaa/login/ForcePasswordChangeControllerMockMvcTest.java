package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.account.UserAccountStatus;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mfa.GoogleMfaProviderConfig;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;
import java.net.URLEncoder;
import java.util.Date;

import static org.cloudfoundry.identity.uaa.mock.util.MfaUtilsMockMVC.createGoogleMfaProvider;
import static org.cloudfoundry.identity.uaa.mock.util.MfaUtilsMockMVC.disableMfaProviderInZone;
import static org.cloudfoundry.identity.uaa.mock.util.MfaUtilsMockMVC.enableMfaProviderInZone;
import static org.cloudfoundry.identity.uaa.mock.util.MfaUtilsMockMVC.performMfaPostVerifyWithCode;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

public class ForcePasswordChangeControllerMockMvcTest extends InjectedMockContextTest {
    private ScimUser user;
    private String adminToken;
    private IdentityProviderProvisioning identityProviderProvisioning;

    @Before
    public void setup() throws Exception {
        String username = new RandomValueStringGenerator().generate() + "@test.org";
        user = new ScimUser(null, username, "givenname","familyname");
        user.setPrimaryEmail(username);
        user.setPassword("secret");
        identityProviderProvisioning = getWebApplicationContext().getBean(JdbcIdentityProviderProvisioning.class);
        adminToken = MockMvcUtils.utils().getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret", null, null);
        user = MockMvcUtils.utils().createUser(getMockMvc(), adminToken, user);
    }

    @Test
    public void force_password_change_happy_path() throws Exception {
        forcePasswordChangeForUser();
        MockHttpSession session = new MockHttpSession();
        performSuccessfulLogin(session);

        assertTrue(getUaaAuthentication(session).isAuthenticated());
        assertTrue(getUaaAuthentication(session).isRequiresPasswordChange());

        checkRequestGotRedirectedTo("/", "/force_password_change", session);

        assertTrue(getUaaAuthentication(session).isAuthenticated());
        assertTrue(getUaaAuthentication(session).isRequiresPasswordChange());

        performForcePasswordChange(session);

        assertTrue(getUaaAuthentication(session).isAuthenticated());
        assertFalse(getUaaAuthentication(session).isRequiresPasswordChange());

        checkRequestGotRedirectedTo("/force_password_change_completed", "http://localhost/", session);
        assertTrue(getUaaAuthentication(session).isAuthenticated());
        assertFalse(getUaaAuthentication(session).isRequiresPasswordChange());
    }

    @Test
    public void force_password_change_with_invalid_password() throws Exception {
        forcePasswordChangeForUser();
        MockHttpSession session = new MockHttpSession();
        Cookie cookie = new Cookie(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf1");

        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaa().getId());
        UaaIdentityProviderDefinition currentConfig = ((UaaIdentityProviderDefinition) identityProvider.getConfig());
        PasswordPolicy passwordPolicy = new PasswordPolicy(15,20,0,0,0,0,0);
        identityProvider.setConfig(new UaaIdentityProviderDefinition(passwordPolicy, null));
        try {
            identityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());

            performSuccessfulLogin(session);

            MockHttpServletRequestBuilder validPost = post("/force_password_change")
                .param("password", "test")
                .param("password_confirmation", "test")
                .session(session)
                .cookie(cookie)
                .with(cookieCsrf());

            getMockMvc().perform(validPost)
                .andExpect(view().name("force_password_change"))
                .andExpect(model().attribute("message", "Password must be at least 15 characters in length."))
                .andExpect(model().attribute("email", user.getPrimaryEmail()));

        } finally {
            identityProvider.setConfig(currentConfig);
            identityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());
        }
    }

    @Test
    public void force_password_when_system_was_configured() throws Exception {
        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaa().getId());
        UaaIdentityProviderDefinition currentConfig = ((UaaIdentityProviderDefinition) identityProvider.getConfig());
        PasswordPolicy passwordPolicy = new PasswordPolicy(4,20,0,0,0,0,0);
        passwordPolicy.setPasswordNewerThan(new Date(System.currentTimeMillis()));
        identityProvider.setConfig(new UaaIdentityProviderDefinition(passwordPolicy, null));

        try {
            identityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());
            MockHttpSession session = new MockHttpSession();

            performSuccessfulLogin(session);

            checkRequestGotRedirectedTo("/", "/force_password_change", session);

            performForcePasswordChange(session);

            checkRequestGotRedirectedTo("/force_password_change_completed", "http://localhost/", session);

            assertTrue(getUaaAuthentication(session).isAuthenticated());
            assertFalse(getUaaAuthentication(session).isRequiresPasswordChange());
        } finally {
            identityProvider.setConfig(currentConfig);
            identityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());
        }
    }

    @Test
    public void submit_password_change_when_not_authenticated() throws Exception {
        forcePasswordChangeForUser();

        MockHttpServletRequestBuilder validPost = post("/force_password_change")
                .param("password", "test")
                .param("password_confirmation", "test");
        validPost.with(cookieCsrf());
        getMockMvc().perform(validPost)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(("http://localhost/login")));
    }

    @Test
    public void force_password_change_with_mfa_not_registered() throws Exception {
        try {
            MfaProvider<GoogleMfaProviderConfig> provider = createGoogleMfaProvider(adminToken, getMockMvc());
            enableMfaProviderInZone("uaa", provider.getName());
            forcePasswordChangeForUser();

            MockHttpSession session = new MockHttpSession();
            performSuccessfulLogin(session);

            assertTrue(getUaaAuthentication(session).isAuthenticated());
            assertTrue(getUaaAuthentication(session).isRequiresPasswordChange());

            checkRequestGotRedirectedTo("/", "/login/mfa/register", session);

            getMockMvc().perform(get("/login/mfa/register")
                .session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(Matchers.containsString("Setup Multifactor Authentication")));

            String redirectAfterMfa = performMfaPostVerifyWithCode(getMockMvc(), session);
            assertEquals("/login/mfa/completed", redirectAfterMfa);

            checkRequestGotRedirectedTo("/", "/force_password_change", session);

            performForcePasswordChange(session);

            getMockMvc().perform(get("/")
                    .session(session))
                    .andExpect(status().isOk());
        } finally {
            //prevents test pollution
            disableMfaProviderInZone("uaa");
        }
    }

    @Test
    public void force_password_change_with_registered_mfa() throws Exception {
        try {
            MockHttpSession session = new MockHttpSession();
            MfaProvider<GoogleMfaProviderConfig> provider = createGoogleMfaProvider(adminToken, getMockMvc());
            enableMfaProviderInZone("uaa", provider.getName());

            performSuccessfulLogin(session);
            assertTrue(getUaaAuthentication(session).isAuthenticated());

            getMockMvc().perform(get("/login/mfa/register")
                    .session(session))
                    .andExpect(status().isOk())
                    .andExpect(content().string(Matchers.containsString("Setup Multifactor Authentication")));

            int code = MockMvcUtils.getMFACodeFromSession(session);
            String redirectAfterMfa = performMfaPostVerifyWithCode(code, getMockMvc(), session, "localhost");

            assertEquals("/login/mfa/completed", redirectAfterMfa);

            checkRequestGotRedirectedTo("/logout.do", "/login", session);
            assertTrue(session.isInvalid());

            forcePasswordChangeForUser();

            session = new MockHttpSession();
            performSuccessfulLogin(session);

            redirectAfterMfa = performMfaPostVerifyWithCode(code, getMockMvc(), session, "localhost");
            assertEquals("/login/mfa/completed", redirectAfterMfa);

            checkRequestGotRedirectedTo("/", "/force_password_change", session);

            performForcePasswordChange(session);

            getMockMvc().perform(get("/")
                    .session(session))
                    .andExpect(status().isOk());
        } finally {
            //prevents test pollution
            disableMfaProviderInZone("uaa");
        }
    }

    private void forcePasswordChangeForUser() throws Exception {
        UserAccountStatus userAccountStatus = new UserAccountStatus();
        userAccountStatus.setPasswordChangeRequired(true);
        String jsonStatus = JsonUtils.writeValueAsString(userAccountStatus);
        getMockMvc().perform(
            patch("/Users/"+user.getId()+"/status")
                .header("Authorization", "Bearer "+ adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(jsonStatus))
            .andExpect(status().isOk());
    }

    private void performForcePasswordChange(MockHttpSession session) throws Exception {
        MockHttpServletRequestBuilder validPost = post("/force_password_change")
                .param("password", "test")
                .param("password_confirmation", "test")
                .session(session)
                .with(cookieCsrf());
        validPost.with(cookieCsrf());

        getMockMvc().perform(validPost)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(("/force_password_change_completed")));
    }

    private void performSuccessfulLogin(MockHttpSession session) throws Exception {
        MockHttpServletRequestBuilder loginRequest = post("/login.do")
                .param("username", user.getUserName())
                .param("password", "secret")
                .session(session)
                .with(cookieCsrf())
                .param(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf1");
        getMockMvc().perform(loginRequest)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"))
                .andExpect(currentUserCookie(user.getId()));

    }

    private ResultMatcher currentUserCookie(String userId) {
        return result -> {
            cookie().value("Current-User", URLEncoder.encode("{\"userId\":\"" + userId + "\"}", "UTF-8")).match(result);
            cookie().maxAge("Current-User", 365*24*60*60);
            cookie().path("Current-User", "").match(result);
        };
    }

    private void checkRequestGotRedirectedTo(String request, String to, MockHttpSession session) throws Exception {
        getMockMvc().perform(get(request)
            .session(session))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl(to));
    }

    private UaaAuthentication getUaaAuthentication(HttpSession session) {
        SecurityContext context = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        return (UaaAuthentication) context.getAuthentication();
    }
}