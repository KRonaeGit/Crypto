package kronaegit.crypto.mac;

import kronaegit.crypto.hash.Hash;
import kronaegit.crypto.CryptoTool;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

public class HMac extends Mac<byte[]> {
    private final Hash hash;
    private int blockSize;

    public HMac(Hash hash, byte[] key) {
        super(key, hash);
        this.hash = hash;
    }
    public HMac(Hash hash, @NotNull String key, Charset charset) {
        this(hash, key.getBytes(charset));
    }
    public HMac(Hash hash, @NotNull String key) {
        this(hash, key, StandardCharsets.UTF_8);
    }

    @Override
    protected byte[] generateKeyObject(byte[] key, Object... data) {
        Hash hash = (Hash) data[0];
        this.blockSize = hash.getInternalBlockSize();
//        this.blockSize = 64;

        // If key is larger than the block size, hash it
        if (key.length > blockSize) {
            key = hash.hash(key);
        }

        // If key is smaller than block size, pad it with 0x00
        if (key.length < blockSize) {
            byte[] paddedKey = new byte[blockSize];
            System.arraycopy(key, 0, paddedKey, 0, key.length);
            key = paddedKey;
        }
        return key;
    }

    @Override
    public byte[] generateMac(byte[] data) throws GeneralSecurityException {
        byte[] key = getKeyObject();

        // Create ipad and opad by XOR'ing the key with 0x36 and 0x5c respectively
        byte[] ipad = new byte[blockSize];
        byte[] opad = new byte[blockSize];
        for (int i = 0; i < blockSize; i++) {
            ipad[i] = (byte) (key[i] ^ 0x36);
            opad[i] = (byte) (key[i] ^ 0x5c);
        }

        // First hash operation: inner hash (ipad + data)
        byte[] innerHash = getHash().hash(CryptoTool.concat(ipad, data));

        // Second hash operation: outer hash (opad + innerHash)
        return getHash().hash(CryptoTool.concat(opad, innerHash));
    }

    public Hash getHash() {
        return hash;
    }
}
