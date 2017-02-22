package me.learning.security;

public class RSAJwtTokenFactoryException extends RuntimeException{
    private static final long serialVersionUID = 5017272796400395351L;

    public RSAJwtTokenFactoryException(String message) {
        super(message);
    }
}
