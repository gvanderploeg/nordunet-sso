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

import com.atlassian.crowd.embedded.api.Directory;
import com.atlassian.crowd.exception.DirectoryInstantiationException;
import com.atlassian.crowd.exception.DirectoryNotFoundException;
import com.atlassian.crowd.exception.GroupNotFoundException;
import com.atlassian.crowd.exception.ObjectNotFoundException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.crowd.manager.application.AliasAlreadyInUseException;
import com.atlassian.crowd.manager.application.AliasManager;
import com.atlassian.crowd.manager.application.ApplicationManager;
import com.atlassian.crowd.manager.application.ApplicationManagerException;
import com.atlassian.crowd.manager.application.ApplicationService;
import com.atlassian.crowd.manager.authentication.TokenAuthenticationManager;
import com.atlassian.crowd.manager.directory.DirectoryManager;
import com.atlassian.crowd.model.application.Application;
import com.atlassian.crowd.model.application.DirectoryMapping;
import com.atlassian.crowd.model.group.Group;
import com.atlassian.crowd.model.group.GroupTemplate;
import com.atlassian.crowd.model.group.GroupType;
import com.atlassian.crowd.model.user.User;
import com.atlassian.crowd.search.EntityDescriptor;
import com.atlassian.crowd.search.builder.QueryBuilder;
import com.atlassian.crowd.search.query.entity.EntityQuery;
import com.atlassian.crowd.service.client.ClientProperties;
import com.atlassian.plugin.webresource.WebResourceManager;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

/**
 * Servlet for claiming old accounts. Copies groups from old account and
 * set the username as an alias for selected applications
 *
 * @author Juha-Matti Leppälä <juha@eduix.fi>
 * @version $Id$
 */
public class ClaimAccountServlet extends HttpServlet {

    private static final Logger log = Logger.getLogger(ClaimAccountServlet.class);
    private DirectoryManager directoryManager;
    private AliasManager aliasManager;
    private ApplicationManager applicationManager;
    private ApplicationService applicationService;
    private TokenAuthenticationManager tokenAuthenticationManager;
    private ClientProperties clientProperties;
    private WebResourceManager webResourceManager;
    private static final Set<String> jiraAppNames;
    private static final Set<String> confluenceAppNames;

    static {
        // TODO: read the application names from a properties file
        // these are used to map groups to applications when creating groups
        jiraAppNames = new HashSet<String>();
        jiraAppNames.add("jira");
        confluenceAppNames = new HashSet<String>();
        confluenceAppNames.add("confluence");
    }

    public ClaimAccountServlet(DirectoryManager directoryManager, AliasManager aliasManager, ApplicationManager applicationManager, ApplicationService applicationService, TokenAuthenticationManager tokenAuthenticationManager, ClientProperties clientProperties, WebResourceManager webResourceManager) {
        this.directoryManager = directoryManager;
        this.aliasManager = aliasManager;
        this.applicationManager = applicationManager;
        this.applicationService = applicationService;
        this.tokenAuthenticationManager = tokenAuthenticationManager;
        this.clientProperties = clientProperties;
        this.webResourceManager = webResourceManager;
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {        
        String username = req.getHeader("REMOTE_USER");
        if (username != null && username.length() > 0) {
            String alias = getCurrentAlias(username);
            String originalDestinationURL = null;
            if (req.getSession().getAttribute(SSOCookieServlet.REDIRECT_ATTRIBUTE) != null) {
                originalDestinationURL = (String) req.getSession().getAttribute(SSOCookieServlet.REDIRECT_ATTRIBUTE);
            }

            writeAccountClaimForm(resp.getWriter(), alias, originalDestinationURL, null);
        } else {
            PrintWriter writer = resp.getWriter();
            writeHtmlStart(writer, null);
            writer.append("<p>You must be logged in to your IDP to claim your account</p>");
            writeHtmlEnd(writer);
        }

    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        List<String> errors = new ArrayList<String>();
        String account = req.getParameter("username");
        String password = req.getParameter("password");
        String username = req.getHeader("REMOTE_USER");
        String originalDestinationURL = (String) req.getSession().getAttribute(SSOCookieServlet.REDIRECT_ATTRIBUTE);
        boolean reclaim = Boolean.parseBoolean(req.getParameter("reclaim"));
        String currentAlias = getCurrentAlias(username);
        if (StringUtils.isBlank(account) || StringUtils.isBlank(password)) {
            errors.add("Username or password was invalid");
            writeAccountClaimForm(resp.getWriter(), currentAlias, originalDestinationURL, errors);
            return;
        }
        LDAPConnection ld = new LDAPConnection();
        try {
            // TODO: read ldap details from a properties file
            ld.connect("ldap.nordu.net", 389);
            ld.authenticate(3, usernameToUID(account), password);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.INVALID_CREDENTIALS) {
                log.info("Error authenticating to LDAP: " + e.getMessage());
                errors.add("Username or password was invalid");
            } else {
                errors.add("Error communicating with LDAP. Contact administration");
                log.error(e);
            }
            writeAccountClaimForm(resp.getWriter(), currentAlias, originalDestinationURL, errors);
            return;
        } finally {
            try {
                ld.disconnect();
            } catch (Exception e) {
            }
        }
        List<Application> applications = null;
        if (currentAlias == null || reclaim) {

            // Copy group data for user only if we're not reclaiming the currently aliased account
            // We have to do this before writing alises since group information
            // is needed to see which applications user can access
            if (!reclaim) {
                try {
                    Directory ldap = directoryManager.findDirectoryByName("NORDUnet");
                    Directory jira = directoryManager.findDirectoryByName("Jira import");
                    List<Group> groupsFromLdap = directoryManager.searchDirectGroupRelationships(ldap.getId(),
                            QueryBuilder.queryFor(Group.class, EntityDescriptor.group()).parentsOf(EntityDescriptor.user()).withName(account).returningAtMost(EntityQuery.ALL_RESULTS));
                    for (Group group : groupsFromLdap) {
                        if (GroupType.GROUP.equals(group.getType())) {
                            if (!addUserToGroup(username, group, confluenceAppNames)) {
                                errors.add("Could not add user to group " + group.getName());
                                log.error("Could not add user to group " + group.getName());
                            }
                        }
                    }
                    List<Group> groupsFromJira = directoryManager.searchDirectGroupRelationships(jira.getId(),
                            QueryBuilder.queryFor(Group.class, EntityDescriptor.group()).parentsOf(EntityDescriptor.user()).withName(account).returningAtMost(EntityQuery.ALL_RESULTS));
                    for (Group group : groupsFromJira) {
                        if (GroupType.GROUP.equals(group.getType())) {
                            if (!addUserToGroup(username, group, jiraAppNames)) {
                                errors.add("Could not add user to group " + group.getName());
                                log.error("Could not add user to group " + group.getName());
                            }
                        }
                    }


                } catch (DirectoryInstantiationException e) {
                    log.error(e);
                } catch (DirectoryNotFoundException e) {
                    log.error(e);
                    errors.add("Could not find directory: " + e.getMessage());
                } catch (OperationFailedException e) {
                    log.error(e);
                }
            }

            // Store aliases for applications that have aliasing enabled
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

            for (Application app : applications) {
                if (app.isAliasingEnabled() && !account.equals(aliasManager.findAliasByUsername(app, username))) {
                    if (log.isInfoEnabled()) {
                        log.info("Setting alias for user " + username + " to " + account + " in application " + app.getName());
                    }
                    try {
                        aliasManager.storeAlias(app, username, account);
                    } catch (AliasAlreadyInUseException e) {
                        log.error("Could not claim user account for user " + username + ". Username " + account + " is already taken");
                        errors.add("Could not claim user account " + account + " for application " + app.getName() + ". Username is already taken");
                    }
                }
            }

            writeAccountClaimInfo(resp.getWriter(), errors, account, username, originalDestinationURL);
        } else {
            writeAccountClaimForm(resp.getWriter(), currentAlias, originalDestinationURL, null);
        }
    }

    private boolean addUserToGroup(String username, Group group, Set<String> applicationNames) {
        Directory directory = null;
        try {
            directory = directoryManager.findDirectoryByName("System users");
        } catch (Exception e) {
            log.error("Could not find user directory for group addition", e);
            return false;
        }
        if (directory != null) {
            try {
                directoryManager.addUserToGroup(directory.getId(), username, group.getName());
                return true;
            } catch (GroupNotFoundException e) {
                log.error("Group not found when adding user " + username + " to group " + group + ": " + e.getMessage() + ". Trying to create group...");
                try {
                    GroupTemplate template = new GroupTemplate(group);
                    template.setDirectoryId(directory.getId());
                    directoryManager.addGroup(directory.getId(), template);
                    // Map the new groups to the given applications
                    if (applicationNames != null && !applicationNames.isEmpty()) {
                        for (String appName : applicationNames) {
                            Application app = applicationManager.findByName(appName);
                            DirectoryMapping directoryMapping = app.getDirectoryMapping(directory.getId());
                            if (directoryMapping != null) {
                                directoryMapping.addGroupMapping(group.getName());
                                try {
                                    applicationManager.update(app);
                                } catch (ApplicationManagerException ex) {
                                    log.error("Error mapping newly created group for application " + app.getName(), ex);
                                }
                            }
                        }
                    }
                    return addUserToGroup(username, group, null);
                } catch (Exception e2) {
                    log.error("Error adding group " + group.getName() + " to directory: " + e2.getMessage());
                }
                return false;
            } catch (Exception e) {
                log.error("Could not access directory to add user " + username + " to group " + group, e);
                return false;
            }
        }
        return false;
    }

    /**
     * Get current alias for user. Assumes that the user will not have several
     * different aliases and returns the first alias it finds
     * @param username
     * @return
     */
    private String getCurrentAlias(String username) {
        if (username != null && username.length() > 0) {
            List<Application> applications = null;
            try {
                final User user = applicationService.findUserByName(applicationManager.findByName(clientProperties.getApplicationName()), username);
                applications = tokenAuthenticationManager.findAuthorisedApplications(user, "crowd");
            } catch (ObjectNotFoundException e) {
                log.error("Could not find user", e);
            } catch (UserNotFoundException e) {
                log.error("User not found", e);
            } catch (DirectoryNotFoundException e) {
                log.error("Directory not found", e);
            } catch (OperationFailedException e) {
                log.error(e);
            }
            String alias = null;
            for (Application app : applications) {

                if (app.isAliasingEnabled()) {
                    alias = aliasManager.findAliasByUsername(app, username);
                    if (alias != null && !username.equals(alias)) {
                        return alias;
                    }
                }
            }
        }
        return null;
    }

    private String usernameToUID(String username) {
        return "uid=" + username + ",ou=people,dc=nordu,dc=net";
    }

    private void writeAccountClaimForm(PrintWriter writer, String alias, String originalDestinationURL, List<String> errors) {
        writeHtmlStart(writer, errors);
        writer.write("<form action='/crowd/plugins/servlet/claimAccount' method='post'>");
        if (alias == null) {
            if (originalDestinationURL != null) {
                writer.write("<p>NORDUnet has migrated to a new Single Sign On setup.</p>");
                writer.write("<p>If you have previously had an account you must claim your old account to keep your permissions and content.</p>");
            } else {
                writer.write("<p>Claim old account by username and LDAP password</p>");
            }
            writer.write("<div>Username: <input type='text' name='username'></div>");
        } else {
            writer.write("<p style='font-weight:bold;'>You have already claimed the account '" + alias + "'. You can not claim another account but you can reclaim this account for new applications by providing your old password.</p>");
            writer.write("<input type='hidden' name='username' value='" + alias + "'>");
            writer.write("<input type='hidden' name='reclaim' value='true'>");
        }
        writer.write("<div>Password: <input type='password' name='password'></div>");
        if (alias == null) {
            writer.write("<div><button type='submit'>Claim account</button></div>");
        } else {
            writer.write("<div><button type='submit'>Reclaim account</button></div>");
        }
        if (originalDestinationURL != null) {
            writer.write("<p>Otherwise proceed to your <a href='");
            writer.write(originalDestinationURL);
            writer.write("'>original destination</a>.</p>");
            writer.write("<p><strong>NOTE If you have had a previous account and proceed to your original destination without claiming that account you will not be able to access your old content.</strong></p>");
        }
        writer.write("</form>");
        writeHtmlEnd(writer);
    }

    private void writeHtmlStart(PrintWriter writer, List<String> errors) {
        writer.write("<html><head><title>Claim account</title>");
        String cssUrl = webResourceManager.getStaticPluginResource("net.nordu.crowd.nordunet-sso:servletSkin", "style.css");
        writer.write("<link rel='stylesheet' href='" + cssUrl + "' type='text/css' title='NORDUnet' />");        
        writer.write("</head><body>");
        writer.write("<div id='container'><div id='top'><h1 title='NORDUnet'>NORDUnet</h1></div><div id='content'>");
        if (errors != null && !errors.isEmpty()) {
            writer.write("<div style='padding: 2px; background: #fcc; border:5px solid #f00; font-weight:bold;'>");
            writer.write("<p>Errors:</p>");
            writer.write("<ul>");
            for (String error : errors) {
                writer.append("<li>").append(error).append("</li>");
            }
            writer.write("</ul></div>");
        }
    }

    private void writeHtmlEnd(PrintWriter writer) {
        writer.write("</div><div id='footer'>");
        writer.write("<p>NORDUnet A/S | Kastruplundgade 22 | DK-2770 Kastrup | DENMARK | Phone +45 32 46 25 00 | Fax +45 45 76 23 66 | info@nordu.net</p>");
        writer.write("</div></div></body></html>");
    }

    private void writeAccountClaimInfo(PrintWriter writer, List<String> errors, String alias, String username, String originalDestinationURL) {
        writeHtmlStart(writer, errors);
        if (errors.isEmpty()) {
            writer.write("<p>Account " + alias + " was claimed succesfully.</p>");
        } else {
            String currentAlias = getCurrentAlias(username);
            if (currentAlias != null) {
                writer.write("<p>Account was claimed partially. If there were errors regarding groups please contact an administrator with a list of the groups.</p>");
            } else {
                writer.write("<p>Could not claim account because of the errors.</p>");
            }
        }
        if (originalDestinationURL != null) {
            writer.write("<p>Please proceed to your original destination <a href='" + originalDestinationURL);
            writer.write("'>" + originalDestinationURL + "</a></p>");
        }
        writeHtmlEnd(writer);
    }

}
