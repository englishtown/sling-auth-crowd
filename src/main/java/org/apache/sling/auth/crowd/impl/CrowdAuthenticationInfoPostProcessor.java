package org.apache.sling.auth.crowd.impl;

import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.jackrabbit.util.Base64;
import org.apache.jackrabbit.util.Text;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.AuthenticationInfoPostProcessor;
import org.apache.sling.commons.osgi.OsgiUtil;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.jcr.base.util.AccessControlUtil;
import org.osgi.service.component.ComponentContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.util.Dictionary;

/**
 * The <code>CrowdAuthenticationInfoPostProcessor</code> class implements
 * the <code>AuthenticationInfoPostProcessor</code> interface.
 *
 * @scr.component immediate="true" label="%auth.crowd.name"
 *                description="%auth.crowd.description"
 *                name="org.apache.sling.auth.crowd.CrowdAuthenticationInfoPostProcessor"
 * @scr.property name="service.description"
 *               value="Apache Sling Atlassian Crowd AuthenticationInfoPostProcessor"
 * @scr.property name="service.vendor" value="The Apache Software Foundation"
 * @scr.service
 */
public class CrowdAuthenticationInfoPostProcessor implements AuthenticationInfoPostProcessor {

    /** default log */
    private final Logger log = LoggerFactory.getLogger(getClass());

    /**
     * @scr.property
     */
    public static final String PROP_CROWD_SERVICE_PREFIX = "crowd.service.prefix";

    /**
     * @scr.property
     */
    public static final String PROP_CROWD_SERVICE_USERNAME = "crowd.service.username";

    /**
     * @scr.property
     */
    public static final String PROP_CROWD_SERVICE_PASSWORD = "crowd.service.password";

    /**
     * The JCR Repository we access to resolve resources
     *
     * @scr.reference
     */
    private SlingRepository repository;

    /** Returns the JCR repository used by this service. */
    protected SlingRepository getRepository() {
        return repository;
    }

    /**
     * Returns an administrative session to the default workspace.
     */
    private Session getSession() throws RepositoryException {
        return getRepository().loginAdministrative(null);
    }

    /**
     * Return the administrative session and close it.
     */
    private void ungetSession(final Session session) {
        if (session != null) {
            try {
                session.logout();
            } catch (Throwable t) {
                log.error("Unable to log out of session: " + t.getMessage(), t);
            }
        }
    }

    private String crowdServicePrefix;
    private String crowdServiceUsername;
    private String crowdServicePassword;

    public void postProcess(AuthenticationInfo info, HttpServletRequest request, HttpServletResponse response)
            throws LoginException
    {
        if (request == null || response == null)
            return;

        if (info != null && info.getUser() != null && info.getPassword() != null) {
            log.info("in postProcess, info.User: " + info.getUser()
                    + ", info.AuthType: " + info.getAuthType());

            try {
                Session session = getSession();
                if (session == null) {
                    log.debug("session is null");
                    return;
                }
                UserManager userManager = AccessControlUtil.getUserManager(session);
                if (userManager == null) {
                    log.debug("userManager is null");
                    return;
                }
                Authorizable authorizable = userManager.getAuthorizable(info.getUser());
                if (authorizable == null) {
                    log.info("authorizable is null, try to authenticate from crowd");

                    //if user not exists but auth with crowd success, create the user
                    if (authenticateByCrowdService(info.getUser(), new String(info.getPassword()))) {
                        log.info("auth success from crowd, create the user");
                        userManager.createUser(info.getUser(), new String(info.getPassword()));
                    }
                }
                else if (!info.getUser().equalsIgnoreCase("admin") && !info.getUser().equalsIgnoreCase("visitor")) {
                    if (authenticateByCrowdService(info.getUser(), new String(info.getPassword()))) {
                        log.info("user exists, overwriting password");
                        ((User) authorizable).changePassword(digestPassword(new String(info.getPassword()), "sha1"));
                    }
                }
            }
            catch (RepositoryException ex) {
                log.debug(ex.toString());
            }
        }
    }

    // ---------- Internals

    /**
     * Digest the given password using the given digest algorithm
     *
     * @param pwd the value to digest
     * @param digest the digest algorithm to use for digesting
     * @return the digested value
     * @throws IllegalArgumentException
     */
    private String digestPassword(String pwd, String digest) throws IllegalArgumentException {
        try {
            StringBuffer password = new StringBuffer();
            password.append("{").append(digest).append("}");
            password.append(Text.digest(digest, pwd.getBytes("UTF-8")));
            return password.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e.toString());
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException(e.toString());
        }
    }

    private boolean authenticateByCrowdService(String username, String password) {
        //formalize crowd username
        username = username.trim();
        if (username.toLowerCase().startsWith("boston\\")) {
            username = username.substring("boston\\".length());
        }
        if (username.contains("@")) {
            username = username.split("@")[0];
        }

        log.info("Try to AuthenticateByCrowdService, User: {}", username);
        if (username.equalsIgnoreCase("admin") || username.equalsIgnoreCase("visitor")) {
            return true;
        }

        try {
            boolean authenticated = authenticateCrowdUser(username, password);
            return authenticated;
        }
        catch (IOException e) {
            log.error("Call Crowd authentication service failed: " + e.getMessage());
        }

        return false;
    }

    private boolean authenticateCrowdUser(String username, String password) throws IOException {
        if (username == null) {
            return false;
        }

        URL url = new URL(crowdServicePrefix + "rest/usermanagement/1/authentication?username=" + username);
        log.info("Crowd service URL: " + url.toString());
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        StringWriter auth = new StringWriter();
        byte[] buffer = (crowdServiceUsername + ":" + crowdServicePassword).getBytes();
        Base64.encode(buffer, 0, buffer.length, auth);
        log.info("The basic auth: " + auth.toString().trim());
        conn.setRequestProperty ("Authorization", "Basic " + auth.toString().trim());
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.setUseCaches(false);
        conn.setAllowUserInteraction(false);
        conn.setRequestProperty("Content-Type", "text/xml");
        conn.setRequestProperty("Accept-Charset", "UTF-8");

        // Create the form content
        try {
            OutputStream out = conn.getOutputStream();
            Writer writer = new OutputStreamWriter(out, "UTF-8");
            writer.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
            writer.write("<password>");
            writer.write("<value>");
            writer.write(password);
            writer.write("</value>");
            writer.write("</password>");
            writer.close();
            out.close();
        }
        catch (IOException e) {
            log.error("Failed to get response, error: " + e.toString());
            return false;
        }

        if (conn.getResponseCode() != 200) {
            log.error("Crowd auth failed: " + username);
            return false;
        }

        return true;
    }

    // ---------- SCR Integration

    private ComponentContext context;

    protected void activate(ComponentContext componentContext) {
        context = componentContext;
        Dictionary<?, ?> props = context.getProperties();

        crowdServicePrefix = OsgiUtil.toString(props.get(
                PROP_CROWD_SERVICE_PREFIX), "").trim();
        if (!crowdServicePrefix.endsWith("/")) {
            crowdServicePrefix += "/";
        }

        crowdServiceUsername = OsgiUtil.toString(props.get(
                PROP_CROWD_SERVICE_USERNAME), "").trim();
        crowdServicePassword = OsgiUtil.toString(props.get(
                PROP_CROWD_SERVICE_PASSWORD), "").trim();

        log.info("in activate, crowdServicePrefix: " + crowdServicePrefix
                + ", crowdServiceUsername: " + crowdServiceUsername
                + ", crowdServicePassword: " + crowdServicePassword);
    }

    protected void deactivate(
            @SuppressWarnings("unused") ComponentContext componentContext) {
        //do nothing
    }

}
