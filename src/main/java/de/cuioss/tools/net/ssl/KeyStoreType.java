/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.net.ssl;

/**
 * The semantic keyStoreType of the Keystore.
 * <p>
 * The specific documentation is inspired from
 * <a href="https://www.java67.com/2012/12/difference-between-truststore-vs.html">...</a>.
 * </p>
 * <p>
 * Whats the difference? keystore is used to store server's own certificate
 * while truststore is used to store the certificate of other parties issued by
 * CA.
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
     * <li>needed when you are setting up server side on SSL. It is used to store
     * server's identity certificate, which server will present to a client on the
     * connection while trust store setup on client side must contain to make the
     * connection work. If you browser to connect to any website over SSL it
     * verifies certificate presented by server against its truststore.</li>
     * <li>java-property: javax.net.ssl.keyStore</li>
     * </ul>
     * .
     */
    KEY_STORE
}
