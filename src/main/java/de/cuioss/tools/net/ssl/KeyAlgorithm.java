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
 * Identifies the key-Algorithm for KeyMaterial-Holder. In order to provide a
 * sensible default-set these are taken from keycloak 11.
 *
 * @author Oliver Wolff
 *
 */
public enum KeyAlgorithm {

    /** {@code null} value. */
    UNDEFINED,

    /** A concrete algorithm that is not this enum / list. */
    OTHER,

    /** <a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard">...</a> */
    AES_128,

    /** <a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard">...</a> */
    AES_192,

    /** <a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard">...</a> */
    AES_256,

    /** <a href="https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm">...</a> */
    ECDSA_P_256,

    /** <a href="https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm">...</a> */
    ECDSA_P_384,

    /** <a href="https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm">...</a> */
    ECDSA_P_521,

    /** <a href="https://en.wikipedia.org/wiki/HMAC">...</a> */
    HMAC_H_256,

    /** <a href="https://en.wikipedia.org/wiki/HMAC">...</a> */
    HMAC_H_384,

    /** <a href="https://en.wikipedia.org/wiki/HMAC">...</a> */
    HMAC_H_512,

    /** <a href="https://en.wikipedia.org/wiki/RSA_(cryptosystem)">...</a> */
    RSA_RS_256,

    /** <a href="https://en.wikipedia.org/wiki/RSA_(cryptosystem)">...</a> */
    RSA_RS_384,

    /** <a href="https://en.wikipedia.org/wiki/RSA_(cryptosystem)">...</a> */
    RSA_RS_512,

    /** <a href="https://en.wikipedia.org/wiki/RSA_(cryptosystem)">...</a> */
    RSA_PS_256,

    /** <a href="https://en.wikipedia.org/wiki/RSA_(cryptosystem)">...</a> */
    RSA_PS_384,

    /** <a href="https://en.wikipedia.org/wiki/RSA_(cryptosystem)">...</a> */
    RSA_PS_512,

    /** <a href="https://en.wikipedia.org/wiki/RSA_(cryptosystem)">...</a> */
    RSA_2048,
}
