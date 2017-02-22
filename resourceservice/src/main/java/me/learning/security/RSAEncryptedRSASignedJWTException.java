package me.learning.security;

/**
 * This exception encapsulates all errors that get thrown in RSAEncryptedRSASignedJWT class
 *
 * @author WolfAlexander nikal@kth.se
 */
public class RSAEncryptedRSASignedJWTException extends RuntimeException{
    private static final long serialVersionUID = -4458342069439696120L;

    public RSAEncryptedRSASignedJWTException(String message) {
        super(message);
    }
}
