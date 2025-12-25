package kronaegit.crypto.hash;

import java.security.NoSuchAlgorithmException;

public class SHA_512 extends GeneralHash {
    public SHA_512() throws NoSuchAlgorithmException {
        super("SHA-512");
    }
    public int getResultSize() { return 64; }
    public int getInternalBlockSize() { return 128; }
}
