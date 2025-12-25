package kronaegit.crypto.hash;

import java.security.NoSuchAlgorithmException;

public class SHA_224 extends GeneralHash {
    public SHA_224() throws NoSuchAlgorithmException {
        super("SHA-224");
    }
    public int getResultSize() { return 28; }
    public int getInternalBlockSize() { return 64; }
}
