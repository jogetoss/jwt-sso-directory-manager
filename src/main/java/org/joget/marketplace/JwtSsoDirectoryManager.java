package org.joget.marketplace;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.joget.apps.app.service.AppUtil;
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.ResourceBundleUtil;
import org.joget.commons.util.SecurityUtil;
import org.joget.directory.dao.RoleDao;
import org.joget.directory.dao.UserDao;
import org.joget.directory.model.Role;
import org.joget.directory.model.User;
import org.joget.directory.model.service.DirectoryManager;
import org.joget.directory.model.service.DirectoryManagerProxyImpl;
import org.joget.directory.model.service.UserSecurityFactory;
import org.joget.plugin.directory.SecureDirectoryManager;
import org.joget.plugin.directory.SecureDirectoryManagerImpl;
import org.joget.workflow.model.dao.WorkflowHelper;
import org.joget.workflow.model.service.WorkflowUserManager;
import org.joget.workflow.util.WorkflowUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class JwtSsoDirectoryManager extends SecureDirectoryManager {

    public SecureDirectoryManagerImpl dirManager;

    public static String SESSION_KEY_REDIRECTION = "ssoRedirect";

    /**
     * Prefix for the session attribute holding an already-verified JWT, keyed by the
     * one-time nonce submitted as the "password" in the auto-submit login form (see
     * buildAutoSubmitLoginForm / ExtSecureDirectoryManagerImpl.authenticate).
     */
    public static final String SESSION_KEY_PENDING_JWT_PREFIX = "jwtSsoPendingJwt_";

    @Override
    public String getName() {
        return "JWT SSO Directory Manager";
    }

    @Override
    public String getDescription() {
        return "Directory Manager with support for JWT SSO";
    }

    @Override
    public String getVersion() {
        return "8.0-SNAPSHOT";
    }

    @Override
    public DirectoryManager getDirectoryManagerImpl(Map properties) {
        if (dirManager == null) {
            dirManager = new ExtSecureDirectoryManagerImpl(properties);
        } else {
            dirManager.setProperties(properties);
        }

        return dirManager;
    }

    @Override
    public String getPropertyOptions() {
        UserSecurityFactory f = (UserSecurityFactory) new SecureDirectoryManagerImpl(null);
        String usJson = f.getUserSecurity().getPropertyOptions();
        usJson = usJson.replaceAll("\\n", "\\\\n");

        String addOnJson = "";
        if (SecureDirectoryManagerImpl.NUM_OF_DM > 1) {
            for (int i = 2; i <= SecureDirectoryManagerImpl.NUM_OF_DM; i++) {
                addOnJson += ",{\nname : 'dm" + i + "',\n label : '@@app.edm.label.addon@@',\n type : 'elementselect',\n";
                addOnJson += "options_ajax : '[CONTEXT_PATH]/web/json/plugin/org.joget.plugin.directory.SecureDirectoryManager/service',\n";
                addOnJson += "url : '[CONTEXT_PATH]/web/property/json/getPropertyOptions'\n}";
            }
        }

        HttpServletRequest request = WorkflowUtil.getHttpServletRequest();
        String callbackUrl = request.getScheme() + "://" + request.getServerName();
        if (request.getServerPort() != 80 && request.getServerPort() != 443) {
            callbackUrl += ":" + request.getServerPort();
        }
        callbackUrl += request.getContextPath() + "/web/json/plugin/org.joget.marketplace.JwtSsoDirectoryManager/service";
        String entityId = callbackUrl;

        String json = AppUtil.readPluginResource(getClass().getName(), "/properties/JwtSsoDirectoryManager.json", new String[]{callbackUrl, usJson, addOnJson}, true, "messages/JwtSsoDirectoryManager");
        return json;
    }

    @Override
    public String getLabel() {
        return "JWT SSO Directory Manager";
    }

    @Override
    public String getClassName() {
        return getClass().getName();
    }

    public static String getCallbackURL() {
        HttpServletRequest request = WorkflowUtil.getHttpServletRequest();
        String callbackUrl = request.getScheme() + "://" + request.getServerName();
        if (request.getServerPort() != 80 && request.getServerPort() != 443) {
            callbackUrl += ":" + request.getServerPort();
        }
        callbackUrl += request.getContextPath() + "/web/json/plugin/org.joget.marketplace.JwtSsoDirectoryManager/service";
        return callbackUrl;
    }

    @Override
    public void webService(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String action = request.getParameter("action");

        DirectoryManagerProxyImpl dm = (DirectoryManagerProxyImpl) AppUtil.getApplicationContext().getBean("directoryManager");
        SecureDirectoryManagerImpl dmImpl = (SecureDirectoryManagerImpl) dm.getDirectoryManagerImpl();

        if (request.getParameter("login") != null) {
            String serverUrl = dmImpl.getPropertyString("serverUrl");
            String clientId = dmImpl.getPropertyString("clientId");
            if (!serverUrl.endsWith("/")) {
                serverUrl += "/";
            }

            String redirect = request.getParameter("redirect");
            String callbackUrl = request.getParameter("callbackUrl");

            if (redirect != null && redirect.trim().length() > 0) {
                request.getSession().setAttribute(SESSION_KEY_REDIRECTION, redirect);
            }

            if (callbackUrl != null && callbackUrl.trim().length() > 0) {
                request.getSession().setAttribute("SESSION_KEY_CALLBACKURL", callbackUrl);
            }

            String finalUrl = serverUrl
                    + "web/json/plugin/org.joget.marketplace.JwtSsoWebService/service"
                    + "?clientId=" + clientId;

            if (redirect != null && redirect.trim().length() > 0) {
                try {
                    finalUrl += "&redirect=" + URLEncoder.encode(redirect, "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    finalUrl += "&redirect=" + redirect;
                }
            }

            if (callbackUrl != null && callbackUrl.trim().length() > 0) {
                try {
                    finalUrl += "&callbackUrl=" + URLEncoder.encode(callbackUrl, "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    finalUrl += "&callbackUrl=" + callbackUrl;
                }
            }

            response.sendRedirect(finalUrl);

            /*

            if (redirect != null && redirect.trim().length() > 0) {
                request.getSession().setAttribute(SESSION_KEY_REDIRECTION, request.getParameter("redirect"));
            }

            response.sendRedirect(serverUrl + "web/json/plugin/org.joget.marketplace.JwtSsoWebService/service?clientId=" + clientId + "&redirect=" + redirect);
             */
        } else {

            //String secretKey = SecurityUtil.decrypt(dmImpl.getPropertyString("secretKey"));
            String publicKeyString = dmImpl.getPropertyString("publicKey");
            boolean userProvisioningEnabled = Boolean.parseBoolean(dmImpl.getPropertyString("userProvisioning"));
            boolean userUpdateEnabled = Boolean.parseBoolean(dmImpl.getPropertyString("userUpdateEnabled"));

            String jwt = request.getParameter("jwt");
            if (jwt == null || jwt.trim().isEmpty()) {
                LogUtil.info(getClass().getName(), "jwt is missing");
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            PublicKey publicKey = loadPublicKey(publicKeyString);
            if (publicKey == null) {
                LogUtil.info(getClass().getName(), "public key is invalid");
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            String username = null;
            String firstName = null;
            String lastName = null;
            String email = null;

            try {
                Claims claims = Jwts.parser()
                        .verifyWith(publicKey)
                        .build()
                        .parseClaimsJws(jwt)
                        .getBody();

                LogUtil.info(getClass().getName(), "claims : " + claims);

                username = claims.get("username", String.class);
                firstName = claims.get("firstName", String.class);
                lastName = claims.get("lastName", String.class);
                email = claims.get("email", String.class);

            } catch (Exception e) {
                LogUtil.error(getClass().getName(), e, "error validating jwt");
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            if (username == null || username.trim().isEmpty()) {
                LogUtil.info(getClass().getName(), "username claim is missing or empty");
                request.getSession().setAttribute("SPRING_SECURITY_LAST_EXCEPTION", new Exception(ResourceBundleUtil.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials")));
                String url = request.getContextPath() + "/web/login?login_error=1";
                response.sendRedirect(url);
            }

            User user = dmImpl.getUserByUsername(username);
            if (user == null && userProvisioningEnabled) {
                // user does not exist, provision
                user = new User();
                user.setId(username);
                user.setUsername(username);
                user.setTimeZone("0");
                user.setActive(1);
                if (email != null && !email.isEmpty()) {
                    user.setEmail(email);
                }

                if (firstName != null && !firstName.isEmpty()) {
                    user.setFirstName(firstName);
                }

                if (lastName != null && !lastName.isEmpty()) {
                    user.setLastName(lastName);
                }

                // set role
                RoleDao roleDao = (RoleDao) AppUtil.getApplicationContext().getBean("roleDao");
                Set roleSet = new HashSet();
                Role r = roleDao.getRole("ROLE_USER");
                if (r != null) {
                    roleSet.add(r);
                }
                user.setRoles(roleSet);
                // add user
                UserDao userDao = (UserDao) AppUtil.getApplicationContext().getBean("userDao");
                userDao.addUser(user);
            } else if (user != null && userProvisioningEnabled && userUpdateEnabled) {
                if (email != null && !email.isEmpty()) {
                    user.setEmail(email);
                }

                if (firstName != null && !firstName.isEmpty()) {
                    user.setFirstName(firstName);
                }

                if (lastName != null && !lastName.isEmpty()) {
                    user.setLastName(lastName);
                }
                WorkflowUserManager wum = (WorkflowUserManager) AppUtil.getApplicationContext().getBean("workflowUserManager");
                wum.setSystemThreadUser(true);
                UserDao userDao = (UserDao) AppUtil.getApplicationContext().getBean("userDao");
                userDao.updateUser(user);

            } else if (user == null && !userProvisioningEnabled) {
                response.sendRedirect(request.getContextPath() + "/web/login?login_error=1");
                return;
            }

            try {
                // Do NOT set SecurityContextHolder directly here - on multi-tenant-hardened
                // Joget servers, EnterpriseJogetSecurityContextImpl silently blocks
                // setAuthentication() calls made from plugin code (only Spring's own
                // AbstractAuthenticationProcessingFilter, and a short list of Joget core
                // classes, are trusted to do this).
                //
                // Instead, submit a real login POST to /j_spring_security_check, which
                // routes through Joget's normal, already-whitelisted login filter chain -
                // Spring's own filter is what ends up calling setAuthentication(), so the
                // hardening check passes.
                //
                // The JWT itself (RS256, ~550-600 chars) can't be used directly as the
                // password: UserAuthenticationService.loginUser(Authentication) silently
                // skips calling authenticate() at all for passwords over 512 characters.
                // So stash the already-verified JWT server-side keyed by a short one-time
                // nonce, and submit the nonce as the password - authenticate() below looks
                // the JWT back up by that nonce.
                String nonce = java.util.UUID.randomUUID().toString();
                request.getSession(true).setAttribute(SESSION_KEY_PENDING_JWT_PREFIX + nonce, jwt);

                WorkflowHelper workflowHelper = (WorkflowHelper) AppUtil.getApplicationContext().getBean("workflowHelper");
                workflowHelper.addAuditTrail(this.getClass().getName(), "authenticate", "Authentication for user " + username + ": " + true);

                response.setContentType("text/html;charset=UTF-8");
                response.getWriter().write(buildAutoSubmitLoginForm(request, username, nonce));
            } catch (IOException | RuntimeException ex) {
                LogUtil.error(getClass().getName(), ex, "Error in JWT SSO login");
                request.getSession().setAttribute("SPRING_SECURITY_LAST_EXCEPTION", new Exception(ResourceBundleUtil.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials")));
                String url = request.getContextPath() + "/web/login?login_error=1";
                response.sendRedirect(url);
            }
        }
    }

    /**
     * A tiny self-submitting HTML form that POSTs the one-time nonce (as the password)
     * to Joget's standard Spring Security login endpoint, so the real login filter
     * chain performs the authentication instead of plugin code touching
     * SecurityContextHolder directly. See SESSION_KEY_PENDING_JWT_PREFIX for why a
     * nonce is used instead of the JWT itself.
     */
    protected String buildAutoSubmitLoginForm(HttpServletRequest request, String username, String nonce) {
        String loginPath = request.getContextPath() + "/j_spring_security_check";

        // CSRFGuard issues a token per target URI, not per session - the token for the
        // current callback URL won't validate against a POST to /j_spring_security_check.
        // Request one scoped to that exact URI so the auto-submitted form isn't rejected
        // as a forged request.
        String csrfTokenName = null;
        String csrfTokenValue = null;
        try {
            csrfTokenName = SecurityUtil.getCsrfTokenName();
            csrfTokenValue = SecurityUtil.getCsrfTokenValue(new LoginUriRequestWrapper(request, loginPath));
        } catch (Exception e) {
            LogUtil.info(getClass().getName(), "could not obtain CSRF token for auto-submit login form: " + e.getMessage());
        }

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><title>Logging in...</title></head>");
        html.append("<body onload=\"document.forms[0].submit()\">");
        html.append("<form method=\"POST\" action=\"").append(escapeHtmlAttribute(loginPath)).append("\">");
        html.append("<input type=\"hidden\" name=\"j_username\" value=\"").append(escapeHtmlAttribute(username)).append("\"/>");
        html.append("<input type=\"hidden\" name=\"j_password\" value=\"").append(escapeHtmlAttribute(nonce)).append("\"/>");
        if (csrfTokenName != null && csrfTokenValue != null && !csrfTokenValue.isEmpty()) {
            html.append("<input type=\"hidden\" name=\"").append(escapeHtmlAttribute(csrfTokenName)).append("\" value=\"").append(escapeHtmlAttribute(csrfTokenValue)).append("\"/>");
        }
        html.append("</form></body></html>");
        return html.toString();
    }

    protected String escapeHtmlAttribute(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;").replace(">", "&gt;");
    }

    protected static PublicKey loadPublicKey(String publicKeyString) {
        PublicKey pub = null;
        try {
            X509EncodedKeySpec ks = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyString));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            pub = kf.generatePublic(ks);
        } catch (Exception e) {
            LogUtil.info(JwtSsoDirectoryManager.class.getName(), "error loading public key: " + e.getMessage());
        }
        return pub;
    }
}
