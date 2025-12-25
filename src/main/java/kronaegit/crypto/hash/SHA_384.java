package kronaegit.crypto.hash;

import java.security.NoSuchAlgorithmException;

public class SHA_384 extends GeneralHash {
    public SHA_384() throws NoSuchAlgorithmException {
        super("SHA-384");
    }
    public int getResultSize() { return 48; }
    public int getInternalBlockSize() { return 128; }
}
