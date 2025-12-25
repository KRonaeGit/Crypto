# Crypto
'Crypto' implements several algorithms in an object-oriented manner.

You can do below things with `Crypto` library:
- Hash(*⚠️MD2*, *⚠️MD5*, *⚠️SHA1*, SHA-xxx, SHA3-xxx, SHA-512/xxx, etc)
- Mac(HMac *with specific hash algorithm*)
- Symmetric Encryption(*⚠️AES-ECB* and AES-GCM)
- Asymmetric Encryption(*⚠️DES* and RSA)
- Checksum(CRC32, Adler32)
- Padding(PKCS#1, PKCS#5, PKCS#7)

Everything is ready for you. Just add below `<dependency>` into your `<dependencies>` tag in `pom.xml`:
```xml
<dependency>
    <groupId>io.github.kronaegit</groupId>
    <artifactId>crypto</artifactId>
    <version>1.3.1</version>
</dependency>
```

## Example use
Hash : example use
```java
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
```

HMac : example use
```java
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
```

AES(Symmetric Encryption) : example use
```java
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
```

RSA(Asymmetric Encryption) : example use

```java
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

```

Checksum : example use
```java
package kronaegit.crypto.checksum;

import kronaegit.crypto.CryptoTool;
import kronaegit.crypto.checksum.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class TestCRC32 {
    public static void main(String[] args) {
        byte[] dataA = "Data A".getBytes(StandardCharsets.UTF_8);
        byte[] dataB = "Data B".getBytes(StandardCharsets.UTF_8);

        CRC32 crc32 = new CRC32();
        byte[] checksumA = crc32.generate(dataA);
        byte[] checksumB = crc32.generate(dataB);

        System.out.println(CryptoTool.toHex(checksumA));
        System.out.println(CryptoTool.toHex(checksumB));

        System.out.println(Arrays.equals(checksumA, checksumB) == Arrays.equals(dataA, dataB)); // true
    }
}
```

Padding : example use
```java
package kronaegit.crypto.padding;

import kronaegit.crypto.CryptoTool;

public class TestPKCS7 {
    public static void main(String[] args) {
        // Prepare random data
        byte[] data = new byte[(int) (Math.floor(Math.random() * 11) + 20)];
        CryptoTool.random().nextBytes(data);

        int blocksize = 16;
        PKCS7Padding padding = new PKCS7Padding(blocksize);

        byte[] padded = padding.pad(data);
        System.out.println(padded.length);
        System.out.println(padded.length % blocksize);
    }
}
```
