package kronaegit.crypto.hash;

import java.security.NoSuchAlgorithmException;

public class SHA3_256 extends GeneralHash {
    public SHA3_256() throws NoSuchAlgorithmException {
        super("SHA3-256");
    }
    public int getResultSize() { return 32; }
    public int getInternalBlockSize() { return 136; }
}
