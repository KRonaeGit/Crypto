package kronaegit.crypto.hash;

import java.security.NoSuchAlgorithmException;

@Deprecated
public class MD2 extends GeneralHash {
    public MD2() throws NoSuchAlgorithmException {
        super("MD2");
    }
    public int getResultSize() { return 16; }
    public int getInternalBlockSize() { return 16; }
}
