package me.learning.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Date;

/**
 * This object represents an RSA encrypted and RSA signed JWT
 * This object allows decrypting and validation of a JWT
 *
 * @author WolfAlexander nikal@kth.se
 */
public class RSAEncryptedRSASignedJWT {
    private static Logger log = LoggerFactory.getLogger(RSAEncryptedRSASignedJWT.class);
    private String encryptedAndSignedToken;
    private SignedJWT decryptedSignedJWT;

    private String decryptionSecret = PropertiesLoader.decryptionSecret;

    /**
     * Constructing object
     * @param encryptedAndSignedToken JWT token in String format
     */
    public RSAEncryptedRSASignedJWT(String encryptedAndSignedToken) {
        this.encryptedAndSignedToken = encryptedAndSignedToken;
    }

    /**
     * Decrypts this JWT
     * @throws RSAEncryptedRSASignedJWTException - if any errors accrues during decryption, message will tell the cause
     */
    public void decrypt() throws RSAEncryptedRSASignedJWTException {
        if(encryptedAndSignedToken == null)
            throw new RSAEncryptedRSASignedJWTException("Cannot perform decryption: no token has been provided");

        try {
            EncryptedJWT encryptedJWT = EncryptedJWT.parse(encryptedAndSignedToken);
            RSADecrypter decrypter = new RSADecrypter(getDecryptionKey());
            encryptedJWT.decrypt(decrypter);

            this.decryptedSignedJWT = encryptedJWT.getPayload().toSignedJWT();

        } catch (ParseException e) {
            log.error(e.getMessage(), e);
            throw new RSAEncryptedRSASignedJWTException(e.getMessage());
        } catch (JOSEException e) {
            log.error("Could not decrypt JWT!", e);
            throw new RSAEncryptedRSASignedJWTException("Could not decrypt JWT!");
        }
    }

    private RSAPrivateKey getDecryptionKey(){
        this.setSecurityProvider();
        KeyPair keyPair = this.getDecryptedKeyPair();

        return (RSAPrivateKey) keyPair.getPrivate();
    }

    private void setSecurityProvider(){
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private KeyPair getDecryptedKeyPair() {
        try {
            PEMEncryptedKeyPair encryptedKeyPair = this.getEncryptedKeyPair();
            PEMDecryptorProvider decryptorProvider = this.getDecryptorProvider();
            JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter();

            return keyConverter.getKeyPair((encryptedKeyPair).decryptKeyPair(decryptorProvider));
        } catch (IOException e) {
            log.error("Could not decrypt private decryption key file", e);
            throw new RSAEncryptedRSASignedJWTException("Could not decrypt provided private decryption key file!");
        }
    }

    private PEMEncryptedKeyPair getEncryptedKeyPair(){
        try{
            File keyFile = this.getKeyFile("security/private_crypt.pem");
            PEMParser pemParser = new PEMParser(new FileReader(keyFile));

            return (PEMEncryptedKeyPair) pemParser.readObject();
        }catch (FileNotFoundException fnfEx){
            log.error("Could not find key file: private_crypt.pem", fnfEx);
            throw new RSAEncryptedRSASignedJWTException("Could not find decryption key file!");
        } catch (IOException e) {
            log.error("Could not read key object!", e);
            throw new RSAEncryptedRSASignedJWTException("Could not read decryption key object!");
        }
    }

    private File getKeyFile(String filename) {
        URL urlToFile = this.getClass().getClassLoader().getResource(filename);

        if(urlToFile == null)
            throw new RSAEncryptedRSASignedJWTException("Could not find " + filename);

        return new File(urlToFile.getPath());
    }

    private PEMDecryptorProvider getDecryptorProvider(){
        if(decryptionSecret == null)
            throw new RSAEncryptedRSASignedJWTException("Decryption secret has not been provided!");

        char[] secret = decryptionSecret.toCharArray();
        return new JcePEMDecryptorProviderBuilder().setProvider("BC").build(secret);
    }

    /**
     * Checks if token signature is valid
     * @return true if signature is valid, false if not
     * @throws RSAEncryptedRSASignedJWTException - if any error occurred during validation, see exception message for exact cause
     */
    public boolean isTokenValid() throws RSAEncryptedRSASignedJWTException{
        if(decryptedSignedJWT == null)
            throw new RSAEncryptedRSASignedJWTException("JWT token has not been decrypted");
        else
            return this.verifyToken();
    }

    private boolean verifyToken() {
        return verifySignature() && !hasTokenExpired();

    }

    private boolean verifySignature(){
        try{
            return decryptedSignedJWT.verify(new RSASSAVerifier(getSignatureKey()));
        }catch (JOSEException e) {
            log.error("Could not verify token signature!", e);
            throw new RSAEncryptedRSASignedJWTException("Could not verify token signature!");
        }
    }


    private RSAPublicKey getSignatureKey(){
        String algorithm = "RSA";

        try{
            byte[] signKey = this.getPublicSignKeyAsByteArray();
            X509EncodedKeySpec spec = new X509EncodedKeySpec(signKey);
            KeyFactory kf = KeyFactory.getInstance(algorithm);

            return (RSAPublicKey) kf.generatePublic(spec);
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage(), e);
            throw new RSAEncryptedRSASignedJWTException("Could not find algorithm: " + algorithm);
        } catch (InvalidKeySpecException e) {
            log.error(e.getMessage(), e);
            throw new RSAEncryptedRSASignedJWTException("Key factory could not get public signature key for given specification");
        }
    }

    private byte[] getPublicSignKeyAsByteArray(){
        try {
            File signKeyfile = getKeyFile("security/public_sign.der");

            return Files.readAllBytes(signKeyfile.toPath());
        } catch (IOException e) {
            log.error("Could not read public sign key from key file!", e);
            throw new RSAEncryptedRSASignedJWTException("Could not read public sign key from key file!");
        }
    }

    private boolean hasTokenExpired(){
        return getTokenClaims().getExpirationTime().before(new Date());
    }


    /**
     * @return JWT token claims
     * @throws RSAEncryptedRSASignedJWTException - if token has not been decrypted or is JWT has invalid payload
     */
    public JWTClaimsSet getTokenClaims(){
        if(decryptedSignedJWT == null)
            throw new RSAEncryptedRSASignedJWTException("Could not get token claims - token appears to be encrypted!");

        try {
            return decryptedSignedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            log.error("Could not get JWT claims set", e);
            throw new RSAEncryptedRSASignedJWTException("Could not get JWT claims set - JSON payload is probably invalid");
        }
    }
}
