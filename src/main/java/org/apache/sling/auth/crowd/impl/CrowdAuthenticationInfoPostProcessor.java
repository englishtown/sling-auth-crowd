package org.apache.sling.auth.crowd.impl;

import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.jackrabbit.util.Base64;
import org.apache.jackrabbit.util.Text;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.AuthenticationInfoPostProcessor;
import org.apache.sling.auth.crowd.CrowdConstants;
import org.apache.sling.commons.osgi.OsgiUtil;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.jcr.base.util.AccessControlUtil;
import org.osgi.service.component.ComponentContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.Value;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Dictionary;
import java.util.Iterator;

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

            Session session = null;
            try {
                session = getSession();
                if (session == null) {
                    log.debug("session is null");
                    return;
                }
                UserManager userManager = AccessControlUtil.getUserManager(session);
                if (userManager == null) {
                    log.debug("userManager is null");
                    return;
                }

                String username = formatUsername(info.getUser());
                String password = new String(info.getPassword());

                info.setUser(username);
                Authorizable authorizable = userManager.getAuthorizable(username);

                if (authorizable == null) {
                    log.info("authorizable is null, try to authenticate from crowd");

                    //if user not exists but auth with crowd success, create the user
                    if (authenticateByCrowdService(username, password)) {
                        log.info("auth success from crowd, create the user");
                        userManager.createUser(username, password);

                        //set user version
                        authorizable = userManager.getAuthorizable(username);
                        String auth_ver = createUserAuthVersion(password);
                        authorizable.setProperty(CrowdConstants.PROP_USER_AUTH_VERSION
                                , session.getValueFactory().createValue(auth_ver));

                        updateUserGroupsFromCrowd(session, userManager, authorizable);
                    }
                }
                else if (!username.equalsIgnoreCase(CrowdConstants.SLING_ADMIN_USERNAME)) {
                    String auth_ver_old = null;
                    Value[] values = authorizable.getProperty(CrowdConstants.PROP_USER_AUTH_VERSION);
                    if (values != null && values.length > 0) {
                        auth_ver_old = values[0].getString();
                    }
                    String auth_ver_new = createUserAuthVersion(password);
                    if (!info.getAuthType().equalsIgnoreCase(CrowdConstants.BASIC_AUTH_TYPE)
                            || !auth_ver_new.equals(auth_ver_old)) {
                        //only on FORM login or BASIC login with password changed,
                        // update user auth version and user groups

                        log.info("old: " + auth_ver_old);
                        log.info("new: " + auth_ver_new);
                        if (authenticateByCrowdService(username, password)) {
                            log.info("user exists, but password changed, overwriting password");
                            ((User)authorizable).changePassword(auth_ver_new);
                            authorizable.setProperty(CrowdConstants.PROP_USER_AUTH_VERSION
                                    , session.getValueFactory().createValue(auth_ver_new));

                            updateUserGroupsFromCrowd(session, userManager, authorizable);
                        }
                    }
                }
            }
            catch (RepositoryException ex) {
                log.debug(ex.toString());
            }
            finally {
                if (session != null)
                    ungetSession(session);
            }
        }
    }

    // ---------- Internals

    private void updateUserGroupsFromCrowd(Session session, UserManager userManager, Authorizable authorizable) {
        try
        {
            //1. get user groups from crowd
            ArrayList<String> groups = getUserGroupsFromCrowd(authorizable.getID());

            //2. for each group, create jcr group if not exists, add user to the jcr group if not already in
            for (int i = 0; i < groups.size(); ++i) {
                final String groupName = groups.get(i);
                Group group = (Group)userManager.getAuthorizable(groupName);
                if (group == null) {
                    group = userManager.createGroup(new Principal() {
                        public String getName() {
                            return groupName;
                        }
                    });
                    Value isCrowdGroup = session.getValueFactory().createValue(true);
                    group.setProperty(CrowdConstants.IS_CROWD_GROUP, isCrowdGroup);
                    log.info("imported crowd group: " + groupName);
                }
                if (!(group.isMember(authorizable))) {
                    group.addMember(authorizable);

                    log.info("added " + authorizable.getID() + " to group: " + groupName);
                }
            }

            //3. get all jcr groups of this user which are imported from crowd,
            // if user no longer in the group, remove user from group
            Iterator<Group> userGroups = authorizable.memberOf();
            while (userGroups.hasNext()) {
                Group group = userGroups.next();
                Value[] values = group.getProperty(CrowdConstants.IS_CROWD_GROUP);
                boolean isCrowdGroup = false;
                if (values.length > 0)
                    isCrowdGroup = values[0].getBoolean();
                if (isCrowdGroup && !groups.contains(group.getID())) {
                    group.removeMember(authorizable);

                    log.info("removed " + authorizable.getID() + " from group: " + group.getID());
                }
            }

        }
        catch(Exception e) {
            log.error("updateUserGroupsFromCrowd, error: " + e.getMessage());
        }
    }
    
    private ArrayList<String> getUserGroupsFromCrowd(String username) {
        ArrayList<String> groups = new ArrayList<String>();

        try {
            URL url = new URL(crowdServicePrefix + "rest/usermanagement/1/user/group/nested?username=" + username);
            log.info("Crowd service URL: " + url.toString());
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            setConnectionAuthorization(conn);
            conn.setDoInput(true);
            conn.setUseCaches(false);
            conn.setAllowUserInteraction(false);
            conn.setRequestProperty("Accept-Charset", "UTF-8");

            BufferedReader in = new BufferedReader(new InputStreamReader(
                    conn.getInputStream()));
            String content = "";
            String buffer;
            while ((buffer = in.readLine()) != null)
                content += buffer;
            in.close();

            if (conn.getResponseCode() == 200) {
                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                factory.setNamespaceAware(true); // never forget this!
                DocumentBuilder builder = factory.newDocumentBuilder();
                Document doc = builder.parse(new ByteArrayInputStream(content.getBytes()));
                NodeList nodeList = doc.getDocumentElement().getChildNodes();
                for (int i = 0; i < nodeList.getLength(); ++i) {
                    groups.add(nodeList.item(i).getAttributes().getNamedItem("name").getNodeValue());
                }
            }
            else
            {
                log.error("getUserGroupsFromCrowd failed, status code: " + conn.getResponseCode());
            }
        }
        catch (Exception e) {
            log.error("getUserGroupsFromCrowd failed, error: " + e.getMessage());
        }

        return groups;
    }
    
    private String createUserAuthVersion(String password) {
        return digestPassword(password, CrowdConstants.USER_PASSWORD_DIGEST_TYPE);
    }

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
        log.info("Try to AuthenticateByCrowdService, User: {}", username);
        if (CrowdConstants.SLING_ADMIN_USERNAME.equalsIgnoreCase(username)) {
            return true;
        }

        try {
            URL url = new URL(crowdServicePrefix + "rest/usermanagement/1/authentication?username=" + username);
            log.info("Crowd service URL: " + url.toString());
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            setConnectionAuthorization(conn);
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
        catch (IOException e) {
            log.error("Call Crowd authentication service failed: " + e.getMessage());
        }

        return false;
    }

    private void setConnectionAuthorization(HttpURLConnection conn) throws IOException {
        StringWriter auth = new StringWriter();
        byte[] buffer = (crowdServiceUsername + ":" + crowdServicePassword).getBytes();
        Base64.encode(buffer, 0, buffer.length, auth);
        log.info("The basic auth: " + auth.toString().trim());
        conn.setRequestProperty ("Authorization", "Basic " + auth.toString().trim());
    }

    private String formatUsername(String username) {
        username = username.trim();
        if (username.toLowerCase().startsWith("boston\\")) {
            username = username.substring("boston\\".length());
        }
        if (username.contains("@")) {
            username = username.split("@")[0];
        }
        return username;
    }

    // ---------- SCR Integration

    protected void activate(ComponentContext componentContext) {
        ComponentContext context = componentContext;
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
