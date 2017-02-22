package me.learning.security;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * This static class represents a generator that will create RSA signed and
 * RSA encrypted JWT tokens
 *
 * @author WolfAlexander nikal@kth.se
 */
@Component
@PropertySource("classpath:security/sign_cred.properties")
public class RSAJwtTokenFactory {
    private static Logger log = LoggerFactory.getLogger(RSAJwtTokenFactory.class);
    private static String signingSecret;

    /**
     * Setting signing secret value from properties
     * @param secret - new secret value
     */
    @Value("${jwt.sign.secret}")
    public void setSigningSecret(String secret){
        signingSecret = secret;
    }

    /**
     * Generates a RSA encrypted and RSA signed JWT from give user information
     * @param userDetails - contains user information needed for token creation
     * @return String representation of JWT token
     * @throws RSAJwtTokenFactoryException if any errors occur during token generation, see exception message for cause
     */
    public static String generateTokenForAUser(UserDetails userDetails) throws RSAJwtTokenFactoryException{
        JWTClaimsSet claimsSet = createJwtClaims(userDetails);

        return generateToken(claimsSet);
    }

    private static JWTClaimsSet createJwtClaims(UserDetails userDetails){
        List<String> grantedAuthorities = getGrantedAuthoritiesAsListOfStrings(userDetails.getAuthorities());

        return new JWTClaimsSet.Builder()
                .subject(userDetails.getUsername())
                .expirationTime(generateExpirationDate())
                .claim("scope", grantedAuthorities)
                .build();
    }

    private static List<String> getGrantedAuthoritiesAsListOfStrings(Collection<? extends GrantedAuthority> grantedAuthorities){
        List<String> grantedAuthoritiesAsStrings = new ArrayList<>();
        for (GrantedAuthority ga : grantedAuthorities){
            grantedAuthoritiesAsStrings.add(ga.getAuthority());
        }

        return grantedAuthoritiesAsStrings;
    }

    private static Date generateExpirationDate(){
        Long oneDayInMilliseconds = 86400000L;
        log.warn("Valid: " + new Date(System.currentTimeMillis() + oneDayInMilliseconds));
        return new Date(System.currentTimeMillis() + oneDayInMilliseconds);
    }

    private static String generateToken(JWTClaimsSet claimsSet){
        RSAPublicKey encryptKey = getEncryptKey();
        RSAPrivateKey signKey = getSigningKey();

        SignedJWT signedJWT = signToken(signKey, claimsSet);
        JWEObject encryptedJWT = encryptToken(encryptKey, signedJWT);

        return encryptedJWT.serialize();
    }

    private static RSAPublicKey getEncryptKey(){
        try{
            File encryptKeyFile = getKeyFile("security/public_crypt.der");
            byte[] encryptKey = getKeyAsByteArray(encryptKeyFile);

            X509EncodedKeySpec spec = new X509EncodedKeySpec(encryptKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");

            return (RSAPublicKey) kf.generatePublic(spec);

        } catch (NoSuchAlgorithmException e) {
            String errorMessage = "Encryption algorithm not found!";
            log.error(errorMessage, e);
            throw new RSAJwtTokenFactoryException(errorMessage);

        } catch (InvalidKeySpecException e) {
            String errorMessage = "Key factory could not get public encryption key for given specification";
            log.error(errorMessage, e);
            throw new RSAJwtTokenFactoryException(errorMessage);

        }
    }

    private static File getKeyFile(String filename) {
        URL urlToFile = RSAJwtTokenFactory.class.getClassLoader().getResource(filename);

        if(urlToFile == null)
            throw new RSAJwtTokenFactoryException("Could not find " + filename);

        return new File(urlToFile.getPath());
    }

    private static byte[] getKeyAsByteArray(File keyFile){
        try {
            return Files.readAllBytes(keyFile.toPath());
        } catch (IOException e) {
            log.error("Could not read bytes from key file!", e);
            throw new RSAJwtTokenFactoryException("Could not read content from key file!");
        }
    }

    private static RSAPrivateKey getSigningKey(){
        setSecurityProvider();
        KeyPair keyPair = getDecryptedKeyPair();

        return (RSAPrivateKey) keyPair.getPrivate();
    }

    private static void setSecurityProvider(){
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private static KeyPair getDecryptedKeyPair(){
        try {
            PEMEncryptedKeyPair encryptedKeyPair = getEncryptedPairKey();
            PEMDecryptorProvider decryptorProvider = getDecryptionProvider();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

            return converter.getKeyPair(encryptedKeyPair.decryptKeyPair(decryptorProvider));
        } catch (IOException e) {
           log.error("ould not decrypt provided private signing key file!", e);
            throw new RSAJwtTokenFactoryException("Could not decrypt provided private signing key file!");
        }
    }

    private static PEMEncryptedKeyPair getEncryptedPairKey(){
        String filename = "security/private_sign.pem";

        try {
            File keyFile = getKeyFile(filename);
            PEMParser pemParser = new PEMParser(new FileReader(keyFile));

            return (PEMEncryptedKeyPair) pemParser.readObject();
        } catch (FileNotFoundException e) {
            log.error("Could not find key file: " + filename, e);
            throw new RSAJwtTokenFactoryException("Could not find key file: " + filename);
        } catch (IOException e) {
            log.error("Could not read key object!", e);
            throw new RSAJwtTokenFactoryException("Could not read decryption key object!");
        }
    }

    private static PEMDecryptorProvider getDecryptionProvider(){
        if (signingSecret == null)
            throw new RSAJwtTokenFactoryException("No signing secret have been provided!");

        char[] secret = signingSecret.toCharArray();
        return new JcePEMDecryptorProviderBuilder().setProvider("BC").build(secret);
    }

    private static SignedJWT signToken(RSAPrivateKey signKey, JWTClaimsSet claimsSet){
        try {
            JWSSigner signer = new RSASSASigner(signKey);

            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
            signedJWT.sign(signer);

            return signedJWT;
        } catch (JOSEException e) {
            log.error(e.getMessage(), e);
            throw new RSAJwtTokenFactoryException(e.getMessage());
        }
    }

    private static JWEObject encryptToken(RSAPublicKey encryptKey, SignedJWT signedToken){
        try {
            JWEObject jwe = createJWEObject(signedToken);
            jwe.encrypt(new RSAEncrypter(encryptKey));

            return jwe;
        } catch (JOSEException e) {
            log.error(e.getMessage(), e);
            throw new RSAJwtTokenFactoryException("Could not encrypt token!");
        }
    }

    private static JWEObject createJWEObject(SignedJWT signedToken){
        return new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128CBC_HS256)
                        .contentType("JWT")
                        .build(),

                new Payload(signedToken)
        );
    }
}