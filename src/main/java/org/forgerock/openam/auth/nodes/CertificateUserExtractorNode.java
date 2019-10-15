package org.forgerock.openam.auth.nodes;

import org.apache.commons.lang.StringUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.iplanet.security.x509.CertUtils;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import java.util.ResourceBundle;
import javax.inject.Inject;
import javax.security.auth.x500.X500Principal;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.GeneralName;
import sun.security.x509.GeneralNameInterface;
import sun.security.x509.OtherName;
import sun.security.x509.RFC822Name;
import sun.security.x509.SubjectAlternativeNameExtension;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

/**
 * Certificate User Extractor Node
 */
@Node.Metadata(outcomeProvider = CertificateUserExtractorNode.CertificateUserExtractorOutcomeProvider.class,
        configClass = CertificateUserExtractorNode.Config.class)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class CertificateUserExtractorNode extends AbstractDecisionNode {

    private static final String BUNDLE = "org/forgerock/openam/auth/nodes/CertificateUserExtractorNode";
    private final Logger logger = LoggerFactory.getLogger(CertificateUserExtractorNode.class);
    private Config config;

    /**
     * Configuration for the node.
     */
    public interface Config {
        @Attribute(order = 100)
        default CertificateAttributeToProfileMappingEnum certificateAttributeToProfileMapping() {
            return CertificateAttributeToProfileMappingEnum.SUBJECT_CN;
        }

        @Attribute(order = 200)
        String otherCertificateAttributeToProfileMapping();

        @Attribute(order = 300)
        default CertificateAttributeProfileMappingExtensionEnum certificateAttributeProfileMappingExtension() {
            return CertificateAttributeProfileMappingExtensionEnum.NONE;
        }
    }

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     */
    @Inject
    public CertificateUserExtractorNode(@Assisted Config config) {
        this.config = config;

    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        JsonValue sharedState = context.sharedState;
        List<X509Certificate> certs = context.transientState.get("X509Certificate").asList(X509Certificate.class);
        X509Certificate theCert = CertificateValidationNode.getX509Certificate(certs, logger);

        if (logger.isDebugEnabled()) {
            logger.debug("Client Cert= \n" + theCert.toString());
        }

        String userTokenId = getTokenFromCert(theCert, config.certificateAttributeToProfileMapping(),
                                              config.otherCertificateAttributeToProfileMapping(),
                                              config.certificateAttributeProfileMappingExtension());

        if (StringUtils.isEmpty(userTokenId)) {
            logger.error("Unable to parse user token ID from Certificate");
            return Action.goTo(CertificateUserExtractorOutcome.NOT_EXTRACTED.name()).build();
        }

        sharedState.put(SharedStateConstants.USERNAME, userTokenId);
        logger.debug("UserTokenId=" + userTokenId);
        return Action.goTo(CertificateUserExtractorOutcome.EXTRACTED.name()).build();
    }

    private String getTokenFromCert(X509Certificate cert, CertificateAttributeToProfileMappingEnum userProfileMapper,
                                    String altUserProfileMapper,
                                    CertificateAttributeProfileMappingExtensionEnum subjectAltExtMapper)
            throws NodeProcessException {
        String userTokenId = null;
        if (!(subjectAltExtMapper == CertificateAttributeProfileMappingExtensionEnum.NONE)) {
            userTokenId = getTokenFromSubjectAltExt(cert, subjectAltExtMapper);
        }
        if (!(userProfileMapper == CertificateAttributeToProfileMappingEnum.NONE) && (userTokenId == null)) {
            userTokenId = getTokenFromSubjectDN(cert, userProfileMapper, altUserProfileMapper);
        }
        return userTokenId;
    }

    private String getTokenFromSubjectDN(X509Certificate cert,
                                         CertificateAttributeToProfileMappingEnum userProfileMapper,
                                         String altUserProfileMapper) {
        /*
         * The certificate has passed the authentication steps
         * so return the part of the certificate as specified
         * in the profile server.
         */
        String userTokenId = null;
        X500Principal subjectPrincipal = cert.getSubjectX500Principal();
        /*
         * Get the Attribute value of the input certificate
         */
        if (logger.isDebugEnabled()) {
            logger.debug("getTokenFromCert: Subject DN : " + CertUtils.getSubjectName(cert));
        }

        if (userProfileMapper == CertificateAttributeToProfileMappingEnum.SUBJECT_DN) {
            userTokenId = CertUtils.getSubjectName(cert);
        } else if (userProfileMapper == CertificateAttributeToProfileMappingEnum.SUBJECT_UID) {
            userTokenId = CertUtils.getAttributeValue(subjectPrincipal, CertUtils.UID);
        } else if (userProfileMapper == CertificateAttributeToProfileMappingEnum.SUBJECT_CN) {
            userTokenId = CertUtils.getAttributeValue(subjectPrincipal, CertUtils.COMMON_NAME);
        } else if (userProfileMapper == CertificateAttributeToProfileMappingEnum.EMAIL_ADDRESS) {
            userTokenId = CertUtils.getAttributeValue(subjectPrincipal, CertUtils.EMAIL_ADDRESS);
            if (userTokenId == null) {
                userTokenId = CertUtils.getAttributeValue(subjectPrincipal, CertUtils.MAIL);
            }
        } else if (userProfileMapper == CertificateAttributeToProfileMappingEnum.OTHER) {
            //  "other" has been selected, so use attribute specified in the
            //  iplanet-am-auth-cert-user-profile-mapper-other attribute,
            //  which is in amAuthCert_altUserProfileMapper.
            userTokenId = CertUtils.getAttributeValue(subjectPrincipal, altUserProfileMapper);
        }
        logger.debug("getTokenFromCert: " + userProfileMapper + " " + userTokenId);
        return userTokenId;
    }

    private String getTokenFromSubjectAltExt(X509Certificate cert,
                                             CertificateAttributeProfileMappingExtensionEnum subjectAltExtMapper)
            throws NodeProcessException {
        String userTokenId = null;
        SubjectAlternativeNameExtension altNameExt;
        try {
            altNameExt = (SubjectAlternativeNameExtension) ((CertificateExtensions) new X509CertInfo(
                    new X509CertImpl(cert.getEncoded()).getTBSCertificate()).get(X509CertInfo.EXTENSIONS)).get(
                    SubjectAlternativeNameExtension.NAME);
        } catch (CertificateException | IOException e) {
            throw new NodeProcessException("Unable to parse SubjectAlternativeNameExtension", e);
        }
        if (altNameExt != null) {
            Iterator itr;
            ObjectIdentifier upnoid;
            try {
                itr = altNameExt.get(SubjectAlternativeNameExtension.SUBJECT_NAME).iterator();
                upnoid = new ObjectIdentifier("1.3.6.1.4.1.311.20.2.3");
            } catch (IOException e) {
                throw new NodeProcessException("Unable to get " + SubjectAlternativeNameExtension.SUBJECT_NAME, e);
            }
            GeneralName generalname;
            while ((userTokenId == null) && itr.hasNext()) {
                generalname = (GeneralName) itr.next();
                if (generalname != null) {
                    if (subjectAltExtMapper == CertificateAttributeProfileMappingExtensionEnum.UPN &&
                            (generalname.getType() == GeneralNameInterface.NAME_ANY)) {
                        OtherName othername = (OtherName) generalname.getName();
                        if (upnoid.equals((Object) (othername.getOID()))) {
                            try {
                                userTokenId = new DerValue(othername.getNameValue()).getData().getUTF8String();
                            } catch (IOException e) {
                                throw new NodeProcessException(e);
                            }
                        }
                    } else if (subjectAltExtMapper == CertificateAttributeProfileMappingExtensionEnum.RFC822_NAME &&
                            (generalname.getType() == GeneralNameInterface.NAME_RFC822)) {
                        userTokenId = ((RFC822Name) generalname.getName()).getName();
                    }
                }
            }
        }
        return userTokenId;
    }

    public enum CertificateAttributeToProfileMappingEnum {
        SUBJECT_DN {
            @Override
            public java.lang.String toString() {
                return "subject DN";
            }
        },
        SUBJECT_CN {
            @Override
            public java.lang.String toString() {
                return "subject CN";
            }
        },
        SUBJECT_UID {
            @Override
            public java.lang.String toString() {
                return "subject UID";
            }
        },
        EMAIL_ADDRESS {
            @Override
            public java.lang.String toString() {
                return "email address";
            }
        },
        OTHER {
            @Override
            public java.lang.String toString() {
                return "other";
            }
        },
        NONE {
            @Override
            public java.lang.String toString() {
                return "none";
            }
        }
    }

    public enum CertificateAttributeProfileMappingExtensionEnum {
        NONE {
            @Override
            public java.lang.String toString() {
                return "none";
            }
        },
        RFC822_NAME {
            @Override
            public java.lang.String toString() {
                return "RFC822Name";
            }
        },
        UPN {
            @Override
            public java.lang.String toString() {
                return "UPN";
            }
        }
    }

    /**
     * The possible outcomes for the Certificate User Extractor NodeNode.
     */
    public enum CertificateUserExtractorOutcome {
        /**
         * Successfully  extracted username.
         */
        EXTRACTED,
        /**
         * Failed to extract username.
         */
        NOT_EXTRACTED
    }

    /**
     * Defines the possible outcomes from this Certificate User Extractor node.
     */
    public static class CertificateUserExtractorOutcomeProvider
            implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE,
                                                                       CertificateUserExtractorOutcomeProvider.class
                                                                               .getClassLoader());
            return ImmutableList.of(
                    new Outcome(CertificateUserExtractorOutcome.EXTRACTED.name(), bundle.getString("extractedOutcome")),
                    new Outcome(CertificateUserExtractorOutcome.NOT_EXTRACTED.name(),
                                bundle.getString("notExtractedOutcome")));
        }
    }
}
