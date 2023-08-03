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

    /** https://en.wikipedia.org/wiki/Advanced_Encryption_Standard */
    AES_128,

    /** https://en.wikipedia.org/wiki/Advanced_Encryption_Standard */
    AES_192,

    /** https://en.wikipedia.org/wiki/Advanced_Encryption_Standard */
    AES_256,

    /** https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm */
    ECDSA_P_256,

    /** https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm */
    ECDSA_P_384,

    /** https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm */
    ECDSA_P_521,

    /** https://en.wikipedia.org/wiki/HMAC */
    HMAC_H_256,

    /** https://en.wikipedia.org/wiki/HMAC */
    HMAC_H_384,

    /** https://en.wikipedia.org/wiki/HMAC */
    HMAC_H_512,

    /** https://en.wikipedia.org/wiki/RSA_(cryptosystem) */
    RSA_RS_256,

    /** https://en.wikipedia.org/wiki/RSA_(cryptosystem) */
    RSA_RS_384,

    /** https://en.wikipedia.org/wiki/RSA_(cryptosystem) */
    RSA_RS_512,

    /** https://en.wikipedia.org/wiki/RSA_(cryptosystem) */
    RSA_PS_256,

    /** https://en.wikipedia.org/wiki/RSA_(cryptosystem) */
    RSA_PS_384,

    /** https://en.wikipedia.org/wiki/RSA_(cryptosystem) */
    RSA_PS_512,

    /** https://en.wikipedia.org/wiki/RSA_(cryptosystem) */
    RSA_2048,
}
