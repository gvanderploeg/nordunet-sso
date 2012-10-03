/*
 * Copyright (c) 2011, NORDUnet A/S
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 *  * Neither the name of the NORDUnet nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package net.nordu.crowd.sso;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.rmi.RemoteException;
import java.util.List;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.atlassian.crowd.exception.DirectoryNotFoundException;
import com.atlassian.crowd.exception.InactiveAccountException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.InvalidAuthorizationTokenException;
import com.atlassian.crowd.exception.ObjectNotFoundException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.crowd.integration.Constants;
import com.atlassian.crowd.integration.http.HttpAuthenticator;
import com.atlassian.crowd.integration.springsecurity.CrowdSSOAuthenticationToken;
import com.atlassian.crowd.manager.application.ApplicationAccessDeniedException;
import com.atlassian.crowd.manager.application.ApplicationManager;
import com.atlassian.crowd.manager.application.ApplicationService;
import com.atlassian.crowd.manager.authentication.TokenAuthenticationManager;
import com.atlassian.crowd.model.application.Application;
import com.atlassian.crowd.model.application.RemoteAddress;
import com.atlassian.crowd.model.authentication.UserAuthenticationContext;
import com.atlassian.crowd.model.authentication.ValidationFactor;
import com.atlassian.crowd.model.user.User;
import com.atlassian.crowd.service.client.ClientProperties;
import com.atlassian.crowd.service.soap.client.SecurityServerClient;
import org.apache.log4j.Logger;

/**
 * Servlet for setting the SSO cookie and redirecting to the wanted destination
 * @author juha
 */
public class SSOCookieServlet extends HttpServlet {

    private static final Logger log = Logger.getLogger(SSOCookieServlet.class);
    private ApplicationService applicationService;
    private ApplicationManager applicationManager;
    private SecurityServerClient securityServerClient;
    private TokenAuthenticationManager tokenAuthenticationManager;
    private HttpAuthenticator httpAuthenticator;
    private ClientProperties clientProperties;
    public static final String REDIRECT_ATTRIBUTE = "ssocookie.redirect";

    public SSOCookieServlet(ApplicationService applicationService, ApplicationManager applicationManager, SecurityServerClient securityServerClient, TokenAuthenticationManager tokenAuthenticationManager, HttpAuthenticator httpAuthenticator, ClientProperties clientProperties) {
        this.applicationService = applicationService;
        this.applicationManager = applicationManager;
        this.securityServerClient = securityServerClient;
        this.tokenAuthenticationManager = tokenAuthenticationManager;
        this.httpAuthenticator = httpAuthenticator;
        this.clientProperties = clientProperties;
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        String requestedApplicationName = clientProperties.getApplicationName();
        String originalRequestUrl = req.getParameter("redirectTo");
        UserAuthenticationContext authCtx = new UserAuthenticationContext();
        String username = req.getHeader("REMOTE_USER");
        if (username == null || (username != null && username.length() == 0)) {
            log.error("No REMOTE_USER header");
            errorPage(res, "Unknown user");
            return;
        }

        List<Application> applications = null;
        try {
            final User user = applicationService.findUserByName(applicationManager.findByName(clientProperties.getApplicationName()), username);
            applications = tokenAuthenticationManager.findAuthorisedApplications(user, "crowd");
        } catch (ObjectNotFoundException e) {
            log.error("Could not find user", e);
        } catch (UserNotFoundException e) {
            log.error("Could not find user", e);
        } catch (DirectoryNotFoundException e) {
            log.error("Could not find directory", e);
        } catch (OperationFailedException e) {
            log.error(e);
        }

        URL reqURL = null;
        // Try to guess the application we want to set the cookie for
        try {
            reqURL = new URL(originalRequestUrl);
            for (Application app : applications) {
                Set<RemoteAddress> remoteAddresses = app.getRemoteAddresses();
                for (RemoteAddress address : remoteAddresses) {
                    if (address.getAddress().equals(reqURL.getHost())) {
                        requestedApplicationName = app.getName();
                        break;
                    }
                }
            }
        } catch (MalformedURLException e) {
        }

        authCtx.setName(username);
        authCtx.setApplication(requestedApplicationName);

        ValidationFactor[] validationFactors = httpAuthenticator.getValidationFactors(req);
        authCtx.setValidationFactors(validationFactors);
        CrowdSSOAuthenticationToken crowdAuthRequest = null;
        try {
            crowdAuthRequest = new CrowdSSOAuthenticationToken(tokenAuthenticationManager.authenticateUserWithoutValidatingPassword(authCtx).getRandomHash());
        } catch (InvalidAuthenticationException e) {
            log.error(e);
            errorPage(res, e.getMessage());
            return;
        } catch (ApplicationAccessDeniedException e) {
            log.error(e);
            errorPage(res, null);
            return;
        } catch (InactiveAccountException e) {
            log.error("Account is inactive: " + e.getMessage());
            errorPage(res, e.getMessage());
            return;
        } catch (ObjectNotFoundException e) {
            log.error("Object not found: " + e.getMessage());
            accessDeniedPage(res);
            return;
        } catch (OperationFailedException e) {
            log.error(e);
            errorPage(res, e.getMessage());
        }

        // fix for Confluence where the response filter is sometimes null.
        if (res != null && crowdAuthRequest != null && crowdAuthRequest.getCredentials() != null) {
            log.trace("Creating cookie");
            // create the cookie sent to the client
            Cookie tokenCookie = buildCookie(crowdAuthRequest.getCredentials().toString());

            if (log.isTraceEnabled()) {
                log.trace("Cookie: " + tokenCookie.getDomain() + " - " + tokenCookie.getName() + " " + tokenCookie.getValue());
            }
            res.addCookie(tokenCookie);
        } else {
            errorPage(res, null);
            return;
        }

        String referer = req.getHeader("referer");
        String gotoUrl = null;
        if (originalRequestUrl != null && originalRequestUrl.length() > 0) {
            gotoUrl = res.encodeRedirectURL(originalRequestUrl);
        } else {
            gotoUrl = res.encodeRedirectURL(referer);
        }
        if (req.getSession().getAttribute("new.user") != null) {
            if (log.isDebugEnabled()) {
                log.debug("New user; redirecting to account claim servlet");
            }
            req.getSession().setAttribute("new.user", null);
            req.getSession().setAttribute(REDIRECT_ATTRIBUTE, gotoUrl);
            String claimAccountUrl = res.encodeRedirectURL("/crowd/plugins/servlet/claimAccount");
            res.sendRedirect(claimAccountUrl);
            return;
        }
        if (log.isTraceEnabled()) {
            log.trace("Redirecting to " + gotoUrl);
        }
        res.sendRedirect(gotoUrl);
        return;
    }

    /**
     * Creates the cookie and sets attributes such as path, domain, and "secure" flag.
     * @param token The SSO token to be included in the cookie
     */
    private Cookie buildCookie(String token) {
        Cookie tokenCookie = new Cookie(getCookieTokenKey(), token);

        // path
        tokenCookie.setPath(Constants.COOKIE_PATH);
        try {
            // domain
            tokenCookie.setDomain(securityServerClient.getCookieInfo().getDomain());
        } catch (RemoteException e) {
            log.error(e);
        } catch (InvalidAuthorizationTokenException e) {
            log.error(e);
        } catch (InvalidAuthenticationException e) {
            log.error(e);
        }

        // "Secure" flag
        tokenCookie.setSecure(Boolean.FALSE);

        return tokenCookie;
    }

    // TODO A real error page
    private void errorPage(HttpServletResponse res, String error) throws IOException {
        if (error != null) {
            res.getWriter().write("ERROR: " + error);
        } else {
            res.getWriter().write("Undefined error");
        }
    }

    private void accessDeniedPage(HttpServletResponse res) throws IOException {
        res.sendError(res.SC_UNAUTHORIZED, "You do not have access to the application");
    }

    public String getCookieTokenKey() {
        return clientProperties.getCookieTokenKey();
    }
}
