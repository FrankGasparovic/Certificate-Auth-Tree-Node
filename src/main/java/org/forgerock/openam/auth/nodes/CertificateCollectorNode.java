package org.forgerock.openam.auth.nodes;

import org.forgerock.guava.common.collect.ListMultimap;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.encode.Base64;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.StringTokenizer;
import javax.inject.Inject;

/**
 * Certificate Collector Node
 */
@Node.Metadata(outcomeProvider = CertificateCollectorNode.CertificateCollectorProvider.class,
        configClass = CertificateCollectorNode.Config.class)
public class CertificateCollectorNode implements Node {

    private static final String BUNDLE = "org/forgerock/openam/auth/nodes/CertificateCollectorNode";
    private final Logger logger = LoggerFactory.getLogger(CertificateCollectorNode.class);
    private final Config config;

    /**
     * Configuration for the node.
     */
    public interface Config {

        @Attribute(order = 100)
        default CertificateCollectionMethod certificateCollectionMethod() {
            return CertificateCollectionMethod.EITHER;
        }

        @Attribute(order = 200)
        String clientCertificateHttpHeaderName();

        @Attribute(order = 300)
        Set<String> trustedRemoteHosts();
    }

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     */
    @Inject
    public CertificateCollectorNode(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        Set<String> trustedRemoteHosts = config.trustedRemoteHosts();
        CertificateCollectionMethod collectionMethod = config.certificateCollectionMethod();

        X509Certificate[] allCerts;
        if (collectionMethod.equals(CertificateCollectionMethod.REQUEST)) {
            allCerts = getCertificatesFromRequest(context);
        } else if (collectionMethod.equals(CertificateCollectionMethod.HEADER) &&
                isHostTrusted(trustedRemoteHosts, context.request.clientIp)) {
            allCerts = getPortalStyleCert(context.request.headers, config.clientCertificateHttpHeaderName());
        } else {
            allCerts = getCertificatesFromRequest(context);
            if (null == (allCerts != null ? allCerts[0] : null)) {
                allCerts = getPortalStyleCert(context.request.headers, config.clientCertificateHttpHeaderName());
            }
        }

        X509Certificate userCert = allCerts != null ? allCerts[0] : null;
        if (null != userCert) {
            List<X509Certificate> certs = new ArrayList<>(Arrays.asList(allCerts));

            return Action.goTo(CertificateCollectorOutcome.COLLECTED.name()).replaceTransientState(
                    context.transientState.put("X509Certificate", JsonValue.json(certs))).build();
        }
        logger.debug("Certificate was not successfully collected based on node configuration and client request");
        return Action.goTo(CertificateCollectorOutcome.NOT_COLLECTED.name()).build();

    }

    private boolean isHostTrusted(Set<String> trustedRemoteHosts, String clientIp) {
        if (trustedRemoteHosts.size() == 0) {
            logger.debug("All hosts are trusted, return true");
            return true;
        }
        if (trustedRemoteHosts.size() == 1) {
            if (trustedRemoteHosts.contains("any")) {
                logger.debug("All hosts are trusted, return true");
                return true;
            } else if (trustedRemoteHosts.contains("none")) {
                logger.debug("No hosts are trusted, return false");
                return false;
            } else if (trustedRemoteHosts.contains(clientIp)) {
                return true;
            }
        }
        return trustedRemoteHosts.contains(clientIp);
    }

    private X509Certificate[] getCertificatesFromRequest(TreeContext context) {
        X509Certificate[] allCerts = (X509Certificate[]) context.request.servletRequest.getAttribute(
                "javax.servlet.request.X509Certificate");
        if (null != allCerts && allCerts.length != 0) {
            if (logger.isDebugEnabled()) {
                X509Certificate userCert = allCerts[0];
                logger.debug("X509Certificate: principal is: " +
                                     userCert.getSubjectDN().getName() +
                                     "\nissuer DN:" + userCert.getIssuerDN().getName() +
                                     "\nserial number:" + userCert.getSerialNumber() +
                                     "\nsubject dn:" + userCert.getSubjectDN().getName());
            }
            return allCerts;
        }
        return null;
    }

    private X509Certificate[] getPortalStyleCert(ListMultimap<String, String> headers,
                                                 String clientCertificateHttpHeaderName) throws NodeProcessException {
        String cert = null;
        if ((clientCertificateHttpHeaderName != null) && (clientCertificateHttpHeaderName.length() > 0)) {
            logger.debug("Checking cert in HTTP header");
            StringTokenizer tok = new StringTokenizer(clientCertificateHttpHeaderName, ",");
            while (tok.hasMoreTokens()) {
                String key = tok.nextToken();

                if (!headers.containsKey(key)) {
                    continue;
                }
                cert = headers.get(key).get(0);
                cert = cert.trim();
                String beginCert = "-----BEGIN CERTIFICATE-----";
                String endCert = "-----END CERTIFICATE-----";
                int idx = cert.indexOf(endCert);
                if (idx != -1) {
                    cert = cert.substring(beginCert.length(), idx);
                    cert = cert.trim();
                }
            }
        }
        logger.debug("Validate cert: " + cert);
        if (cert == null || cert.equals("")) {
            logger.debug("Certificate: no cert from HttpServletRequest header");
            return null;
        }

        byte[] decoded = Base64.decode(cert);
        if (decoded == null) {
            throw new NodeProcessException("CertificateFromParameter decode failed, possibly invalid Base64 input");
        }

        logger.debug("CertificateFactory.getInstance.");
        CertificateFactory cf;
        X509Certificate userCert;
        try {
            cf = CertificateFactory.getInstance("X.509");
            userCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decoded));
        } catch (Exception e) {
            throw new NodeProcessException("CertificateFromParameter(X509Cert)", e);
        }

        if (userCert == null) {
            throw new NodeProcessException("Certificate is null");
        }

        if (logger.isDebugEnabled()) {
            logger.debug("X509Certificate: principal is: " +
                                 userCert.getSubjectDN().getName() +
                                 "\nissuer DN:" + userCert.getIssuerDN().getName() +
                                 "\nserial number:" + userCert.getSerialNumber() +
                                 "\nsubject dn:" + userCert.getSubjectDN().getName());
        }
        return new X509Certificate[]{userCert};
    }

    public enum CertificateCollectionMethod {
        REQUEST,
        HEADER,
        EITHER
    }

    /**
     * The possible outcomes for the CertificateCollectorNode.
     */
    public enum CertificateCollectorOutcome {
        /**
         * Successful authentication.
         */
        COLLECTED,
        /**
         * Authentication failed.
         */
        NOT_COLLECTED
    }

    /**
     * Defines the possible outcomes from this Certificate Collector node.
     */
    public static class CertificateCollectorProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(CertificateCollectorNode.BUNDLE,
                                                                       CertificateCollectorProvider.class
                                                                               .getClassLoader());
            return ImmutableList.of(
                    new Outcome(CertificateCollectorOutcome.COLLECTED.name(), bundle.getString("collectedOutcome")),
                    new Outcome(CertificateCollectorOutcome.NOT_COLLECTED.name(),
                                bundle.getString("notCollectedOutcome")));
        }
    }

}
