package kronaegit.crypto.hash;

import java.security.NoSuchAlgorithmException;

public class SHA3_512 extends GeneralHash {
    public SHA3_512() throws NoSuchAlgorithmException {
        super("SHA3-512");
    }
    public int getResultSize() { return 64; }
    public int getInternalBlockSize() { return 72; }
}
