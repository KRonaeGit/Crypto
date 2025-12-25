package kronaegit.crypto.hash;

import java.security.NoSuchAlgorithmException;

public class SHA_256 extends GeneralHash {
    public SHA_256() throws NoSuchAlgorithmException {
        super("SHA-256");
    }
    public int getResultSize() { return 32; }
    public int getInternalBlockSize() { return 64; }
}
