package kronaegit.crypto.cipher.asymmetric;

import kronaegit.crypto.CryptoTool;
import kronaegit.crypto.hash.Hash;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSA extends DigitalSignatureAlgorithm<RSA.KeyPair, RSA.PrivateKey, RSA.PublicKey> {
    private final SecureRandom random;
    private final Cipher cipher = Cipher.getInstance("RSA");

    public RSA(KeyPair keypair) throws NoSuchPaddingException, NoSuchAlgorithmException {
        super(keypair);
        this.random = CryptoTool.random();
    }
    public RSA(KeyPair keypair, @NotNull SecureRandom random) throws NoSuchPaddingException, NoSuchAlgorithmException {
        super(keypair);
        this.random = random;
    }

    @Override
    public byte[] encrypt(byte[] data) throws GeneralSecurityException {
        RSAPublicKey pubKey = getPublicKey().getKey();

        synchronized (cipher) {
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            return cipher.doFinal(data);
        }
    }

    @Override
    public byte[] decrypt(byte[] data) throws GeneralSecurityException {
        if (!hasPrivateKey())
            throw new GeneralSecurityException("Cannot decrypt without private key!");
        RSAPrivateKey prvKey = getPrivateKey().getKey();

        synchronized (cipher) {
            cipher.init(Cipher.DECRYPT_MODE, prvKey);
            return cipher.doFinal(data);
        }
    }

    @Override
    public byte[] sign(byte[] data, Hash hash) throws GeneralSecurityException {
        if (!hasPrivateKey())
            throw new GeneralSecurityException("Cannot sign without private key!");
        RSAPrivateKey prvKey = getPrivateKey().getKey();

        byte[] digest = hash.hash(data);
        synchronized (cipher) {
            cipher.init(Cipher.ENCRYPT_MODE, prvKey);
            return cipher.doFinal(digest);
        }
    }

    @Override
    public boolean verify(byte[] data, byte[] signature, Hash hash) throws GeneralSecurityException {
        RSAPublicKey pubKey = getPublicKey().getKey();

        synchronized (cipher) {
            cipher.init(Cipher.DECRYPT_MODE, pubKey);
            byte[] decryptedSignature = cipher.doFinal(signature);

            byte[] actualDigest = hash.hash(data);
            return MessageDigest.isEqual(decryptedSignature, actualDigest);
        }
    }



    public static class PrivateKey extends AsymmetricEncryption.PrivateKey<PrivateKey, PublicKey, RSAPrivateCrtKey> {
        public PrivateKey(byte[] key) throws GeneralSecurityException {
            super(key);
        }

        @Override
        protected @NotNull RSAPrivateCrtKey generateKeyObject(byte[] key) throws GeneralSecurityException {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(key);
            java.security.PrivateKey prvKey = keyFactory.generatePrivate(pkcs8Spec);
            if (!(prvKey instanceof RSAPrivateCrtKey rsaPrvKey))
                throw new GeneralSecurityException("This is not a valid RSA private key: It is PKCS8EncodeKeySpec but, not RSA private key.");
            return rsaPrvKey;
        }

        @Override
        public @NotNull PublicKey generatePublicKey() throws GeneralSecurityException {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(getKey().getModulus(), getKey().getPublicExponent());
            java.security.PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
            byte[] publicKeyBytes = pubKey.getEncoded();
            return new PublicKey(publicKeyBytes);
        }
    }

    public static class PublicKey extends AsymmetricEncryption.PublicKey<PrivateKey, PublicKey, RSAPublicKey> {
        public PublicKey(byte[] key) throws GeneralSecurityException {
            super(key);
        }

        @Override
        protected @NotNull RSAPublicKey generateKeyObject(byte[] key) throws GeneralSecurityException {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(key);
            java.security.PublicKey pubKey = keyFactory.generatePublic(x509Spec);
            if(!(pubKey instanceof RSAPublicKey rsaPubKey))
                throw new GeneralSecurityException("This is not a valid RSA public key: It is X509EncodeKeySpec but, not RSA public key.");

            return rsaPubKey;
        }
    }


    public static class KeyPair extends AsymmetricEncryption.KeyPair<PrivateKey, PublicKey> {
        public KeyPair(@Nullable PrivateKey prv, @Nullable PublicKey pub) throws GeneralSecurityException {
            super(prv, pub);
        }
        public KeyPair(SecureRandom random, int keysize) throws GeneralSecurityException {
            super(random, keysize);
        }

        @Override
        protected void generateKeyPair(SecureRandom random, int keySize) throws GeneralSecurityException {
            try {
                // Create a KeyPairGenerator instance for RSA.
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                // Initialize the generator with a key size (e.g., 2048 bits) and the provided SecureRandom.
                keyPairGenerator.initialize(keySize, random);
                // Generate the key pair.
                java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();
                // Convert the generated keys to our custom RSA key classes.
                setKeys(new PrivateKey(keyPair.getPrivate().getEncoded()), new PublicKey(keyPair.getPublic().getEncoded()));
            } catch (GeneralSecurityException e) {
                // Wrap in a RuntimeException if key generation fails.
                throw new GeneralSecurityException("Failed to generate RSA key pair", e);
            }
        }
    }
}
