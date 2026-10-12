package org.joget.marketplace;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * Makes SecurityUtil.getCsrfTokenValue() issue a token scoped to the login URI
 * instead of the current request's URI (CSRFGuard's token service keys tokens by
 * request URI).
 */
public class LoginUriRequestWrapper extends HttpServletRequestWrapper {
    private final String loginPath;

    public LoginUriRequestWrapper(HttpServletRequest request, String loginPath) {
        super(request);
        this.loginPath = loginPath;
    }

    @Override
    public String getRequestURI() {
        return loginPath;
    }
}
