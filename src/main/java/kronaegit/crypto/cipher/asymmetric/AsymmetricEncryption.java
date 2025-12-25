package kronaegit.crypto.cipher.asymmetric;

import kronaegit.crypto.cipher.Cipher;
import kronaegit.crypto.cipher.Key;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public abstract class AsymmetricEncryption<KP extends AsymmetricEncryption.KeyPair<S, P>, S extends AsymmetricEncryption.PrivateKey<S,P,?>, P extends AsymmetricEncryption.PublicKey<S,P,?>> implements Cipher {
    public static abstract class KeyPair<S extends PrivateKey<S,P,?>, P extends PublicKey<S,P,?>> {
        private S prv;
        private P pub;

        public KeyPair(SecureRandom random, int keySize) throws GeneralSecurityException {
            generateKeyPair(random, keySize);
        }
        public KeyPair(@Nullable S prv, @Nullable P pub) throws GeneralSecurityException {
            setKeys(prv, pub);
        }

        protected void setKeys(@Nullable S prv, @Nullable P pub) throws GeneralSecurityException {
            if(prv == null && pub == null)
                throw new IllegalArgumentException("Fully empty key pair? (null, null)");
            if(prv != null && pub != null) {
                if(!prv.generatePublicKey().equals(pub)) {
                    throw new GeneralSecurityException("Private key and public key mismatches!");
                }
            }
            this.prv = prv;
            this.pub = pub;
        }

        public boolean hasPrivateKey() {
            return prv != null;
        }

        public @Nullable S getPrivateKey() {
            if(!hasPrivateKey()) return null;
            return prv;
        }
        public @NotNull P getPublicKey() throws GeneralSecurityException {
            if(pub == null) {
                if(prv == null) throw new RuntimeException(); // never
                pub = prv.generatePublicKey();
            }
            return pub;
        }

        protected abstract void generateKeyPair(SecureRandom random, int keySize) throws GeneralSecurityException;
    }
    public static abstract class PrivateKey<S extends PrivateKey<S,P,K>, P extends PublicKey<S,P,?>, K> extends Key<K> {
        public PrivateKey(byte[] key) throws GeneralSecurityException {
            super(key);
        }
        public abstract @NotNull P generatePublicKey() throws GeneralSecurityException;
    }
    public static abstract class PublicKey<S extends PrivateKey<S,P,?>, P extends PublicKey<S,P,K>, K> extends Key<K> {
        public PublicKey(byte[] key) throws GeneralSecurityException {
            super(key);
        }
    }

    private final KP keypair;
    public AsymmetricEncryption(KP keypair) {
        this.keypair = keypair;
    }
    public KeyPair<S, P> getKeyPair() {
        return keypair;
    }
    public boolean hasPrivateKey() {
        return keypair.hasPrivateKey();
    }
    public @Nullable S getPrivateKey() {
        if(!hasPrivateKey()) return null;
        return keypair.getPrivateKey();
    }
    public P getPublicKey() throws GeneralSecurityException {
        return keypair.getPublicKey();
    }

    public abstract byte[] encrypt(byte[] data) throws GeneralSecurityException;
    public abstract byte[] decrypt(byte[] data) throws GeneralSecurityException;
}
