package org.joget.marketplace;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.joget.apps.app.service.AppUtil;
import org.joget.commons.util.LogUtil;
import org.joget.directory.model.service.UserSecurity;
import org.joget.directory.model.service.UserSecurityFactory;
import org.joget.plugin.directory.SecureDirectoryManagerImpl;
import org.joget.plugin.directory.dao.UserExtraDao;
import org.joget.plugin.directory.dao.UserPasswordHistoryDao;
import org.joget.workflow.util.WorkflowUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class ExtSecureDirectoryManagerImpl extends SecureDirectoryManagerImpl implements UserSecurityFactory {

    private UserSecurity userSecurity;

    public ExtSecureDirectoryManagerImpl(Map properties) {
        super(properties);
    }

    /**
     * Called by Joget's own WorkflowAuthenticationProvider / UserAuthenticationService
     * during a normal Spring Security login POST (j_username/j_password). The JWT SSO
     * login form (see JwtSsoDirectoryManager.buildAutoSubmitLoginForm) submits a
     * short-lived one-time nonce as the "password" - if it resolves to a JWT stashed
     * in the current session that verifies against the configured public key with a
     * matching username claim, treat it as authenticated.
     *
     * A nonce is used instead of the JWT itself because
     * UserAuthenticationService.loginUser(Authentication) silently skips calling
     * authenticate() at all when the password exceeds 512 characters - longer than a
     * typical RS256 JWT.
     *
     * This lets the actual session get established from inside Joget's own,
     * already-whitelisted authentication filter chain, instead of plugin code calling
     * SecurityContextHolder.setAuthentication() directly (which multi-tenant-hardened
     * servers block - see EnterpriseJogetSecurityContextImpl).
     */
    @Override
    public boolean authenticate(String username, String password) {
        if (isValidSsoNonce(username, password)) {
            return true;
        }
        return super.authenticate(username, password);
    }

    protected boolean isValidSsoNonce(String username, String nonce) {
        if (username == null || nonce == null || nonce.isEmpty()) {
            return false;
        }

        HttpServletRequest request = WorkflowUtil.getHttpServletRequest();
        if (request == null) {
            return false;
        }
        HttpSession session = request.getSession(false);
        if (session == null) {
            return false;
        }

        String sessionKey = JwtSsoDirectoryManager.SESSION_KEY_PENDING_JWT_PREFIX + nonce;
        Object pending = session.getAttribute(sessionKey);
        if (pending == null) {
            // not a nonce we issued - treat as a normal password attempt
            return false;
        }
        // one-time use
        session.removeAttribute(sessionKey);
        String jwt = pending.toString();

        String publicKeyString = getPropertyString("publicKey");
        if (publicKeyString == null || publicKeyString.trim().isEmpty()) {
            return false;
        }

        PublicKey publicKey = JwtSsoDirectoryManager.loadPublicKey(publicKeyString);
        if (publicKey == null) {
            return false;
        }

        try {
            Claims claims = Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseClaimsJws(jwt)
                    .getBody();

            String claimUsername = claims.get("username", String.class);
            return username.equals(claimUsername);
        } catch (Exception e) {
            LogUtil.info(getClass().getName(), "JWT SSO authenticate: pending token for " + username + " did not verify: " + e.getMessage());
            return false;
        }
    }

    /**
     * Override this method to return a custom UserSecurity object to customize the login form footer
     * @return 
     */
    @Override
    public UserSecurity getUserSecurity() {
        if (userSecurity == null) {
            userSecurity = new ExtUserSecurityImpl();
            UserExtraDao userExtraDao = (UserExtraDao)AppUtil.getApplicationContext().getBean("userExtraDao");
            UserPasswordHistoryDao userPasswordHistoryDao = (UserPasswordHistoryDao)AppUtil.getApplicationContext().getBean("userPasswordHistoryDao");
            ((ExtUserSecurityImpl)userSecurity).setUserExtraDao(userExtraDao);
            ((ExtUserSecurityImpl)userSecurity).setUserPasswordHistoryDao(userPasswordHistoryDao);
        }
        Map<String, Object> usProperties = new HashMap<String, Object>();
        Map<String, Object> properties = getProperties();
        if (properties != null) {
            usProperties.putAll(properties);
        }
        userSecurity.setProperties(usProperties);
        return userSecurity;
    }
    
}

