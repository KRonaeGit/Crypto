package kronaegit.crypto.cipher.asymmetric;

import kronaegit.crypto.cipher.asymmetric.*;
import kronaegit.crypto.hash.*;
import kronaegit.crypto.hash.Hash;

import kronaegit.crypto.CryptoTool;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class TestRSA {
    public static void main(String[] args) throws GeneralSecurityException {
        int keysize = 2048; // General key sizes: 1024, 2048, 3072, 4096
        SecureRandom random = CryptoTool.random(); // Generates SecureRandom instance.

        // Generate new keypair with 'SecureRandom random'
        RSA.KeyPair secretKeypair = new RSA.KeyPair(random, keysize); // A keypair with private&public keys
        RSA secretRSA = new RSA(secretKeypair); // RSA with public&private(secret) keys.

        RSA.KeyPair publicKeypair = new RSA.KeyPair(null, secretKeypair.getPublicKey()); // A keypair with ONLY public key
        RSA publicRSA = new RSA(publicKeypair); // RSA with ONLY public key

        byte[] data = "data".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = publicRSA.encrypt(data); // Encrypt with public key
        byte[] decrypted = secretRSA.decrypt(encrypted); // Decrypt with private key
        System.out.println(Arrays.equals(data, decrypted)); // expected: true

        Hash hash = new SHA_512();
        byte[] signature = secretRSA.sign(data, hash); // Sign with private key
        boolean verify = publicRSA.verify(data, signature, hash); // Verify with public key
        System.out.println(verify); // expected: true
    }
}
