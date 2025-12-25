package kronaegit.crypto.hash;

import java.security.NoSuchAlgorithmException;

public class SHA3_384 extends GeneralHash {
    public SHA3_384() throws NoSuchAlgorithmException {
        super("SHA3-384");
    }
    public int getResultSize() { return 48; }
    public int getInternalBlockSize() { return 104; }
}
