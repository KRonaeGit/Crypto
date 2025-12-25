package kronaegit.crypto.hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public abstract class GeneralHash implements Hash {
    private final MessageDigest messageDigest;
    private final String algorithm;

    public GeneralHash(String algorithm) throws NoSuchAlgorithmException {
        this.algorithm = algorithm;
        messageDigest = MessageDigest.getInstance(algorithm);
    }

    @Override
    public byte[] hash(byte[] data) {
        synchronized(messageDigest) {
            messageDigest.reset();
            return messageDigest.digest(data);
        }
    }

    public String getAlgorithm() {
        return algorithm;
    }
}
