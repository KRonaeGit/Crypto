package kronaegit.crypto.hash;

import kronaegit.crypto.hash.*;
import kronaegit.crypto.CryptoTool;

import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

public class TestHashes {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        Hash hasher = new SHA_256(); // throws NoSuchAlgorithmException

        // Prepare UTF8 data
        byte[] data = "data".getBytes(StandardCharsets.UTF_8);

        // Hash data
        byte[] hash = hasher.hash(data);

        // Uppercase: true, lowercase: false
        String hexHash = CryptoTool.toHex(hash, false);

        // expected: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
        System.out.println(hexHash);
    }
}