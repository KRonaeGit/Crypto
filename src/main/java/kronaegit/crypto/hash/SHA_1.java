package kronaegit.crypto.hash;

import java.security.NoSuchAlgorithmException;

@Deprecated
public class SHA_1 extends GeneralHash {
    public SHA_1() throws NoSuchAlgorithmException {
        super("SHA-1");
    }
    public int getResultSize() { return 20; }
    public int getInternalBlockSize() { return 64; }
}
