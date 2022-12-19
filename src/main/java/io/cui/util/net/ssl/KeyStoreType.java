package io.cui.util.net.ssl;

/**
 * The semantic keyStoreType of the Keystore.
 * <p>
 * The specific documentation is inspired from
 * https://www.java67.com/2012/12/difference-between-truststore-vs.html.
 * </p>
 * <p>
 * Whats the difference? keystore is used to store server's own certificate while truststore is
 * used to store the certificate of other parties issued by CA.
 * </p>
 *
 * @author Oliver Wolff
 *
 */
public enum KeyStoreType {

    /**
     *
     * A truststore is
     * <ul>
     * <li>used to store others credential: Certificates from CAs or you company,
     * Customers,...</li>
     * <li>java-property: javax.net.ssl.trustStore</li>
     * <li>Default location for Java installations:
     * <ul>
     * <li>Oracle: JAVA_HOME/JRE/Security/cacerts</li>
     * <li>Zulu / OpenJDK: JAVA_HOME/lib/security/cacerts</li>
     * </ul>
     * </li>
     * </ul>
     * .
     */
    TRUST_STORE,

    /**
     * A keystore is
     * <ul>
     * <li>used to store your credential (server or client)</li>
     * <li>needed when you are setting up server side on SSL. It is used to store server's
     * identity certificate, which server will present to a client on the connection while trust
     * store setup on client side must contain to make the connection work. If you browser to
     * connect to any website over SSL it verifies certificate presented by server against its
     * truststore.</li>
     * <li>java-property: javax.net.ssl.keyStore</li>
     * </ul>
     * .
     */
    KEY_STORE
}