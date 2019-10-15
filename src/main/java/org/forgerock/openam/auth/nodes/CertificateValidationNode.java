/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */


package org.forgerock.openam.auth.nodes;

import static com.fasterxml.jackson.annotation.JsonAutoDetect.*;

import org.apache.commons.lang.StringUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.opendj.ldap.LdapUrl;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.iplanet.am.util.SystemProperties;
import com.sun.identity.security.cert.AMCRLStore;
import com.sun.identity.security.cert.AMCertPath;
import com.sun.identity.security.cert.AMCertStore;
import com.sun.identity.security.cert.AMLDAPCertStoreParameters;
import com.sun.identity.shared.Constants;
import com.sun.identity.shared.datastruct.CollectionHelper;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.Vector;
import javax.inject.Inject;

/**
 * Certificate Validation Node
 */
@Node.Metadata(outcomeProvider = CertificateValidationNode.CertificateValidationOutcomeProvider.class,
        configClass = CertificateValidationNode.Config.class)
@JsonAutoDetect(fieldVisibility = Visibility.ANY)
public class CertificateValidationNode extends AbstractDecisionNode {
    private static final String BUNDLE = "org/forgerock/openam/auth/nodes/CertificateValidationNode";
    private final Logger logger = LoggerFactory.getLogger(CertificateValidationNode.class);
    private final Config config;

    /**
     * Configuration for the node.
     */
    public interface Config {

        @Attribute(order = 100)
        default boolean matchCertificateInLdap() { return false; }

        @Attribute(order = 200)
        default boolean checkCertificateExpiry() { return false; }

        @Attribute(order = 300)
        default String ldapCertificateAttribute() { return "CN"; }

        @Attribute(order = 400)
        default boolean matchCertificateToCRL() { return false; }

        @Attribute(order = 500)
        default String crlMatchingCertificateAttribute() { return "CN"; }

        @Attribute(order = 600)
        String crlHttpParameters();

        @Attribute(order = 700)
        default boolean cacheCRLsInMemory() { return true; }

        @Attribute(order = 800)
        default boolean updateCRLsFromDistributionPoint() { return true; }

        @Attribute(order = 900)
        default boolean ocspValidationEnabled() { return false; }

        @Attribute(order = 1000)
        default Set<String> certificateLdapServers() { return Collections.singleton(getDirectoryServerURL()); }

        @Attribute(order = 1100)
        Set<String> ldapSearchStartDN();

        @Attribute(order = 1200)
        default String userBindDN() { return "cn=Directory Manager"; }

        @Attribute(order = 1300)
        @Password
        default char[] userBindPassword() {
            return new char[]{' '};
        }

        @Attribute(order = 1400)
        default boolean sslEnabled() { return false; }
    }

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     */
    @Inject
    public CertificateValidationNode(@Assisted Config config) {
        this.config = config;
    }

    private static String getDirectoryServerURL() {
        final String host = SystemProperties.get(Constants.AM_DIRECTORY_HOST);
        final String port = SystemProperties.get(Constants.AM_DIRECTORY_PORT);

        if (host != null && port != null) {
            return host + ":" + port;
        } else {
            return "";
        }
    }

    static X509Certificate getX509Certificate(List<X509Certificate> certs, Logger logger) throws NodeProcessException {
        X509Certificate theCert = !certs.isEmpty() ? certs.get(0) : null;

        if (theCert == null) {
            logger.debug("Certificate: no cert passed in.");
            throw new NodeProcessException(
                    "No certificate passed from Shared State. Check configuration of the certificate collector node");
        }
        return theCert;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        AMLDAPCertStoreParameters ldapParam = null;
        List<X509Certificate> certs = context.transientState.get("X509Certificate").asList(X509Certificate.class);
        X509Certificate theCert = getX509Certificate(certs, logger);

        if (config.checkCertificateExpiry()) {
            try {
                theCert.checkValidity();
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                logger.debug("Certificate Expired", e);
                return Action.goTo(CertificateValidationOutcome.EXPIRED.name()).build();
            }
        }


        if (config.matchCertificateInLdap() || config.matchCertificateToCRL() || config.ocspValidationEnabled()) {
            ldapParam = setLdapStoreParam();

        }

        if (config.matchCertificateInLdap()) {
            if (StringUtils.isEmpty(config.ldapCertificateAttribute())) {
                throw new NodeProcessException(
                        "Ldap Certificate Attribute is empty in node configuration but needed to match certificate in" +
                                " LDAP");
            }
            if (AMCertStore.getRegisteredCertificate(ldapParam, theCert, config.ldapCertificateAttribute()) == null) {
                logger.error("Certificate not found in the directory");
                return Action.goTo(CertificateValidationOutcome.NOT_FOUND.name()).build();
            }
        }

        if (config.matchCertificateToCRL() || config.ocspValidationEnabled()) {
            if (!isCertificatePathValid(certs)) {
                logger.error("Certificate path is not valid");
                return Action.goTo(CertificateValidationOutcome.PATH_VALIDATION_FAILED.name()).build();
            }
            if (!isCertificateRevoked(certs, ldapParam)) {
                logger.error("Certificate is revoked");
                return Action.goTo(CertificateValidationOutcome.REVOKED.name()).build();
            }
        }

        return Action.goTo(CertificateValidationOutcome.TRUE.name()).build();
    }

    private String[] trimItems(String[] items) {
        String[] trimmedItems = new String[items.length];
        for (int i = 0; i < items.length; i++) {
            trimmedItems[i] = items[i].trim();
        }
        return trimmedItems;
    }

    private boolean isCertificatePathValid(List<X509Certificate> theCerts)
            throws NodeProcessException {

        AMCertPath certPath;
        try {
            certPath = new AMCertPath(null);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new NodeProcessException("Unable to create the Certificate Path", e);
        }
        return certPath.verify(theCerts.toArray(new X509Certificate[0]), false, false);

    }

    private boolean isCertificateRevoked(List<X509Certificate> theCerts, AMLDAPCertStoreParameters ldapParam)
            throws NodeProcessException {
        Vector<X509CRL> certificateRevocationLists = new Vector<>();
        for (X509Certificate cert : theCerts) {
            X509CRL crl = AMCRLStore.getCRL(ldapParam, cert,
                                            trimItems(config.crlMatchingCertificateAttribute().split(",")));
            if (crl != null) {
                certificateRevocationLists.add(crl);
            }
        }
        if (logger.isDebugEnabled()) {
            logger.debug("CertificateRevocationLists size = " + certificateRevocationLists.size());
            if (certificateRevocationLists.size() > 0) {
                logger.debug("CRL = " + certificateRevocationLists.toString());
            }
        }
        AMCertPath certPath;
        try {
            certPath = new AMCertPath(certificateRevocationLists);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new NodeProcessException("Unable to create the Certificate Path", e);
        }

        return certPath.verify(theCerts.toArray(new X509Certificate[0]), config.matchCertificateToCRL(),
                               config.ocspValidationEnabled());

    }

    private AMLDAPCertStoreParameters setLdapStoreParam() throws NodeProcessException {
        /*
         * Setup the LDAP certificate directory service context for
         * use in verification of the users certificates.
         */
        Map<String, Set<String>> configMap = new HashMap<String, Set<String>>() {{
            put("certificateLdapServers", config.certificateLdapServers());
            put("ldapSearchStartDN", config.ldapSearchStartDN());
        }};

        String serverHost = CollectionHelper.getServerMapAttr(configMap, "certificateLdapServers");
        if (serverHost != null) {
            // set LDAP Parameters
            try {
                LdapUrl ldapUrl = LdapUrl.valueOf("ldap://" + serverHost);
                AMLDAPCertStoreParameters ldapParam = AMCertStore.setLdapStoreParam(ldapUrl.getHost(),
                                                                                    ldapUrl.getPort(),
                                                                                    config.userBindDN(),
                                                                                    String.valueOf(
                                                                                            config.userBindPassword()),
                                                                                    CollectionHelper.getServerMapAttr(
                                                                                            configMap,
                                                                                            "ldapSearchStartDN"),
                                                                                    config.crlHttpParameters(),
                                                                                    config.sslEnabled());
                ldapParam.setDoCRLCaching(config.cacheCRLsInMemory());
                ldapParam.setDoCRLUpdate(config.updateCRLsFromDistributionPoint());
                return ldapParam;
            } catch (Exception e) {
                throw new NodeProcessException("Unable to set LDAP Server configuration", e);
            }
        }
        throw new NodeProcessException("Unable to set LDAP Server configuration, LDAP Configuration is null");

    }

    /**
     * The possible outcomes for the Certificate Validation node.
     */
    public enum CertificateValidationOutcome {
        /**
         * Successful authentication.
         */
        TRUE,
        /**
         * Authentication failed.
         */
        FALSE,
        /**
         * The certificate is expired.
         */
        NOT_FOUND,
        /**
         * The certificate is expired.
         */
        EXPIRED,
        /**
         * The certificate path validation failed.
         */
        PATH_VALIDATION_FAILED,
        /**
         * The certificate is revoked.
         */
        REVOKED,


    }

    /**
     * Defines the possible outcomes from this Certificate Validation node.
     */
    public static class CertificateValidationOutcomeProvider
            implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(CertificateValidationNode.BUNDLE,
                                                                       CertificateValidationOutcomeProvider.class
                                                                               .getClassLoader());
            return ImmutableList.of(
                    new Outcome(CertificateValidationOutcome.TRUE.name(), bundle.getString("trueOutcome")),
                    new Outcome(CertificateValidationOutcome.FALSE.name(), bundle.getString("falseOutcome")),
                    new Outcome(CertificateValidationOutcome.NOT_FOUND.name(), bundle.getString("notFound")),
                    new Outcome(CertificateValidationOutcome.EXPIRED.name(), bundle.getString("expiredOutcome")),
                    new Outcome(CertificateValidationOutcome.PATH_VALIDATION_FAILED.name(),
                                bundle.getString("pathValidationFailed")),
                    new Outcome(CertificateValidationOutcome.REVOKED.name(), bundle.getString("revoked")));
        }
    }
}
