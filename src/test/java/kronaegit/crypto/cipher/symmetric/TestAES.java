package kronaegit.crypto.cipher.symmetric;

import kronaegit.crypto.cipher.symmetric.*;
import kronaegit.crypto.hash.*;
import kronaegit.crypto.CryptoTool;

import java.security.GeneralSecurityException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class TestAES {
    public static void main(String[] args) throws GeneralSecurityException {
        byte[] plainKey = "key".getBytes(StandardCharsets.UTF_8);
        byte[] key = new SHA_256().hash(plainKey); // Make key to 256bits. (to use AES-256)
        byte[] data = "data".getBytes(StandardCharsets.UTF_8);

        // You can set IV length, tag length with another constructor.
        AES_GCM aes = new AES_GCM(key);

        // encrypted[0~11]: IV
        // encrypted[12~]: Encrypted Data
        byte[] encrypted = aes.encrypt(data);

        // expected: d34b0867f205ce6d277434f0efe93f05978a8d82f7fccebe3b2fbc976ece70bf
        System.out.println(CryptoTool.toHex(encrypted));

        byte[] decrypted = aes.decrypt(encrypted);

        // expected: true
        System.out.println(Arrays.equals(data, decrypted));
    }
}
