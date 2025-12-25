package kronaegit.crypto.hash;

import java.security.NoSuchAlgorithmException;

public class SHA_512_256 extends GeneralHash {
    public SHA_512_256() throws NoSuchAlgorithmException {
        super("SHA-512/256");
    }
    public int getResultSize() { return 32; }
    public int getInternalBlockSize() { return 128; }
}
