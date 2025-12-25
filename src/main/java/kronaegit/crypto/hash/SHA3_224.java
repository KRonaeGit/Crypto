package kronaegit.crypto.hash;

import java.security.NoSuchAlgorithmException;

public class SHA3_224 extends GeneralHash {
    public SHA3_224() throws NoSuchAlgorithmException {
        super("SHA3-224");
    }
    public int getResultSize() { return 28; }
    public int getInternalBlockSize() { return 144; }
}
