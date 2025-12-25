package kronaegit.crypto.mac;

import kronaegit.crypto.mac.*;
import kronaegit.crypto.hash.*;
import kronaegit.crypto.CryptoTool;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

public class TestHMacs {
    public static void main(String[] args) throws GeneralSecurityException {
        byte[] key = "key".getBytes(StandardCharsets.UTF_8);
        byte[] data = "data".getBytes(StandardCharsets.UTF_8);

        Hash hash = new SHA_256();
        HMac hmac = new HMac(hash, key);

        // Generate HMac SHA256 signature
        byte[] signature = hmac.generateMac(data);

        // Uppercase: true, lowercase: false
        String hexSignature = CryptoTool.toHex(signature, false);

        // expected: 5031fe3d989c6d1537a013fa6e739da23463fdaec3b70137d828e36ace221bd0
        System.out.println(hexSignature);

        boolean verify = hmac.verifyMac(data, signature);
        System.out.println(verify); // expected: true
    }
}