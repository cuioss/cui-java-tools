package io.cui.util.net.ssl;

/**
 * Identifies the key-Algorithm for KeyMaterial-Holder. In order to provide a sensible default-set
 * these are taken from keycloak 11.
 *
 * @author Oliver Wolff
 *
 */
public enum KeyAlgorithm {

    /** {@code null} value. */
    UNDEFINED,

    /** A concrete algorithm that is not not this enum / list. */
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
