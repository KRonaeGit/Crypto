package kronaegit.crypto.hash;

import java.security.NoSuchAlgorithmException;

public class SHA_512_244 extends GeneralHash {
    public SHA_512_244() throws NoSuchAlgorithmException {
        super("SHA-512/244");
    }
    public int getResultSize() { return 28; }
    public int getInternalBlockSize() { return 128; }
}
