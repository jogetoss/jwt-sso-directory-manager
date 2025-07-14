package org.joget.marketplace;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.workflow.security.WorkflowUserDetails;
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.ResourceBundleUtil;
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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class JwtSsoDirectoryManager extends SecureDirectoryManager {

    public SecureDirectoryManagerImpl dirManager;

    public static String SESSION_KEY_REDIRECTION = "ssoRedirect";

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
            if(redirect != null && redirect.trim().length() > 0){
                request.getSession().setAttribute(SESSION_KEY_REDIRECTION, request.getParameter("redirect"));
            }

            response.sendRedirect(serverUrl + "web/json/plugin/org.joget.marketplace.JwtSsoWebService/service?clientId=" + clientId);

        } else {

            //String secretKey = SecurityUtil.decrypt(dmImpl.getPropertyString("secretKey"));
            String publicKeyString = dmImpl.getPropertyString("publicKey");
            boolean userProvisioningEnabled = Boolean.parseBoolean(dmImpl.getPropertyString("userProvisioning"));

            String jwt = request.getParameter("jwt");
            if (jwt == null || jwt.isEmpty()) {
                LogUtil.info(getClass().getName(), "jwt is missing");
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            PublicKey publicKey = loadPublicKey(publicKeyString);

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
            } else if (user == null && !userProvisioningEnabled) {
                response.sendRedirect(request.getContextPath() + "/web/login?login_error=1");
                return;
            }

            try {
                // get authorities
                UserDetails details = new WorkflowUserDetails(user);
                Collection<Role> roles = dm.getUserRoles(user.getUsername());
                List<GrantedAuthority> gaList = new ArrayList<>();
                if (roles != null && !roles.isEmpty()) {
                    for (Role role : roles) {
                        GrantedAuthority ga = new SimpleGrantedAuthority(role.getId());
                        gaList.add(ga);
                    }
                }

                // login user
                UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(user.getUsername(), "", gaList);
                result.setDetails(details);

                SecurityContext securityContext = SecurityContextHolder.getContext();
                securityContext.setAuthentication(result);

                HttpSession session = request.getSession(true);
                session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);

                //WorkflowUserManager wum = (WorkflowUserManager) AppUtil.getApplicationContext().getBean("workflowUserManager");
                //wum.setCurrentThreadUser(user);

                // add audit trail
                WorkflowHelper workflowHelper = (WorkflowHelper) AppUtil.getApplicationContext().getBean("workflowHelper");
                workflowHelper.addAuditTrail(this.getClass().getName(), "authenticate", "Authentication for user " + username + ": " + true);

                // redirect
                String relayState = request.getParameter("RelayState");
                if (relayState != null && !relayState.isEmpty()) {
                    response.sendRedirect(relayState);
                } else {
                    Object redirect = request.getSession().getAttribute(SESSION_KEY_REDIRECTION);

                    if(redirect != null){
                        String redirectUrl = (String) redirect;
                        response.sendRedirect(redirectUrl);
                    }else{
                        SavedRequest savedRequest = new HttpSessionRequestCache().getRequest(request, response);
                        String savedUrl = "";
                        if (savedRequest != null) {
                            savedUrl = savedRequest.getRedirectUrl();
                        } else {
                            savedUrl = request.getContextPath();
                        }
                        response.sendRedirect(savedUrl);
                    }
                }

            } catch (IOException | RuntimeException ex) {
                LogUtil.error(getClass().getName(), ex, "Error in JWT SSO login");
                request.getSession().setAttribute("SPRING_SECURITY_LAST_EXCEPTION", new Exception(ResourceBundleUtil.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials")));
                String url = request.getContextPath() + "/web/login?login_error=1";
                response.sendRedirect(url);
            }
        }
    }

    protected PublicKey loadPublicKey(String publicKeyString) {
        PublicKey pub = null;
        try {
            X509EncodedKeySpec ks = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyString));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            pub = kf.generatePublic(ks);
        } catch (Exception e) {
            LogUtil.info(getClass().getName(), "error loading public key: " + e.getMessage());
        }
        return pub;
    }
}
