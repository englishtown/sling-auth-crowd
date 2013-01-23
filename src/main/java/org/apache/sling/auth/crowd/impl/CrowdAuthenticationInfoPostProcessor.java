package org.apache.sling.auth.crowd.impl;

import org.apache.sling.api.resource.LoginException;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.AuthenticationInfoPostProcessor;
import org.apache.sling.commons.osgi.OsgiUtil;
import org.osgi.service.component.ComponentContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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

    private String crowdServicePrefix;
    private String crowdServiceUsername;
    private String crowdServicePassword;

    public void postProcess(AuthenticationInfo info, HttpServletRequest request, HttpServletResponse response)
            throws LoginException
    {
        if (info != null && info.getUser() != null && info.getPassword() != null && request != null) {
            log.info("in postProcess, info.User: " + info.getUser()
                    + ", info.Password: " + new String(info.getPassword())
                    + ", info.AuthType: " + info.getAuthType());

        }
    }

    // ---------- SCR Integration

    private ComponentContext context;

    protected void activate(ComponentContext componentContext) {
        context = componentContext;
        Dictionary<?, ?> props = context.getProperties();

        crowdServicePrefix = OsgiUtil.toString(props.get(
                PROP_CROWD_SERVICE_PREFIX), "");
        crowdServiceUsername = OsgiUtil.toString(props.get(
                PROP_CROWD_SERVICE_USERNAME), "");
        crowdServicePassword = OsgiUtil.toString(props.get(
                PROP_CROWD_SERVICE_PASSWORD), "");

        log.info("in activate, crowdServicePrefix: " + crowdServicePrefix
                + ", crowdServiceUsername: " + crowdServiceUsername
                + ", crowdServicePassword: " + crowdServicePassword);
    }

    protected void deactivate(
            @SuppressWarnings("unused") ComponentContext componentContext) {
        //do nothing
    }

}
