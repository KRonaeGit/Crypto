package kronaegit.crypto.hash;

import java.security.NoSuchAlgorithmException;

@Deprecated
public class MD5 extends GeneralHash {
    public MD5() throws NoSuchAlgorithmException {
        super("MD5");
    }
    public int getResultSize() { return 16; }
    public int getInternalBlockSize() { return 64; }
}
