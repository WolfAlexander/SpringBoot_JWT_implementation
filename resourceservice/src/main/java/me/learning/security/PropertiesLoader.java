package me.learning.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;

/**
 * This static class will load needed properties from files
 *
 * @author WolfAlexander nikal@kth.se
 */
@Component
@PropertySource("classpath:security/decrypt_cred.properties")
public class PropertiesLoader {
    protected static String decryptionSecret;

    /**
     * Static values has to be entered using a method
     * @param newSecret - value from the properties file
     */
    @Value("${jwt.decrypt.secret}")
    public void setSecret(String newSecret){
        decryptionSecret = newSecret;
    }
}
