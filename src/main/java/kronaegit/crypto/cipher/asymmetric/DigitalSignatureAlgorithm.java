package kronaegit.crypto.cipher.asymmetric;

import kronaegit.crypto.hash.Hash;

import java.security.GeneralSecurityException;

public abstract class DigitalSignatureAlgorithm<KP extends AsymmetricEncryption.KeyPair<S, P>, S extends AsymmetricEncryption.PrivateKey<S,P,?>, P extends AsymmetricEncryption.PublicKey<S,P,?>> extends AsymmetricEncryption<KP, S, P>   {
    public DigitalSignatureAlgorithm(KP keypair) {
        super(keypair);
    }

    public abstract byte[] sign(byte[] data, Hash hash) throws GeneralSecurityException;
    public abstract boolean verify(byte[] data, byte[] signature, Hash hash) throws GeneralSecurityException;
    public <E extends Throwable> byte[] validate(byte[] data, byte[] signature, Hash hash, E e)
            throws E, GeneralSecurityException {
        if (!verify(data, signature, hash)) throw e;
        return data;
    }
}
