# Crypto
'Crypto' implements several algorithms in an object-oriented manner.

You can do below things with `Crypto` library:
- Hash(MD2, MD5, SHA-xxx, SHA3-xxx, SHA-512/xxx, etc)
- Mac(ex. HMac)
- Cipher(AES, DES and RSA)
- Checksum(CRC32, Adler32)
- Padding(PKCS#1, PKCS#5, PKCS#7)

Everything is ready for you. Just add below `<dependency>` into your `<dependencies>` tag in `pom.xml`:
```xml
<dependency>
    <groupId>io.github.kronaegit</groupId>
    <artifactId>crypto</artifactId>
    <version>1.2.0</version>
</dependency>
```

## Example use
Hash : example use
```java
import kronaegit.crypto.hash.*;

public class Test {
    public static void main(String[] args) {
        Hash hash = new SHA_256(); // Select hash. In this example: SHA-256

        String data = "Most Important DATA";

        byte[] hashBytes = hash.hash(data);
        String hashString = hash.hashToString(data); // Hex

        System.out.println(hashString);
    }
}
```

HMac : example use
```java
import kronaegit.crypto.hash.*;
import kronaegit.crypto.mac.*;

public class Test {
    public static void main(String[] args) {
        String key = "Top Secret KEY";
        String data = "Most Important DATA";
        
        HMac hmac = new HMac(new SHA_256(), key); // Select hash. In this example: SHA-256
        
        String signature = hmac.generateMacString(data); // Generates HMac signature
        System.out.println(signature);
        
        boolean verify = hmac.verifyMac(data, signature);
        System.out.println(verify); // true
    }
}
```

AES(Symmetric Encryption) : example use
```java
import kronaegit.crypto.cipher.symmetric.*;

public class Test {
    public static void main(String[] args) {
        String key = "Top Secret KEY";
        String data = "Most Important DATA";
        System.out.println(data);
        
        AES aes = new AES(key);
        
        byte[] encrypted = aes.encrypt(data);
        String decrypted = aes.decryptToString(encrypted);

        System.out.println(decrypted); // decrypted .equals( data ) == true
    }
}
```

RSA(Asymmetric Encryption) : example use

```java
import kronaegit.crypto.CryptoTool;
import kronaegit.crypto.cipher.asymmetric.*;
import kronaegit.crypto.hash.*;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

public class Test {
    public static void main(String[] args) {
        int keysize = 2048; // General key sizes: 1024, 2048, 3072, 4096
        SecureRandom random = CryptoTool.random(); // Generates SecureRandom instance.

        // Generate new keypair with 'SecureRandom random'
        RSA.KeyPair secretKeypair = new RSA.KeyPair(random, keysize); // A keypair with private&public keys
        RSA secretRSA = new RSA(secretKeypair); // RSA with public&private(secret) keys.

        RSA.KeyPair publicKeypair = new RSA.KeyPair(null, secretKeypair.getPublicKey()); // A keypair with ONLY public key
        RSA publicRSA = new RSA(publicKeypair); // RSA with ONLY public key 

        byte[] data = "Most Important DATA".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = publicRSA.encrypt(data); // Encrypt with public key
        byte[] decrypted = secretRSA.decrypt(encrypted); // Decrypt with private key
        System.out.println(Arrays.equals(data, decrypted)); // true

        Hash hash = new SHA_512();
        byte[] signature = secretRSA.sign(data, hash); // Sign with private key
        boolean verify = publicRSA.verify(data, signature, hash); // Verify with public key
        System.out.println(verify); // true
    }
}
```

Checksum : example use
```java
import kronaegit.crypto.checksum.*;

import java.util.Objects;

public class Test {
    public static void main(String[] args) {
        String dataA = "Data A";
        String dataB = "Data B";

        CRC32 crc32 = new CRC32();
        byte[] checksumA = crc32.generate(dataA);
        byte[] checksumB = crc32.generate(dataB);

        System.out.println(Arrays.equals(checksumA, checksumB) == Objects.equals(dataA, dataB)); // true
    }
}
```

Padding : example use
```java
import kronaegit.crypto.CryptoTool;
import kronaegit.crypto.padding.*;

import java.util.Objects;

public class Test {
    public static void main(String[] args) {
        byte[] data = new byte[Math.floor(Math.random() * 11) + 20]; // random length 20~30
        CryptoTool.random().nextBytes(data); // Fill data with SecureRandom

        int blocksize = 16; // Select blocksize. In this example: 16bytes/block
        PKCS7Padding padding = new PKCS7Padding(blocksize);

        byte[] padded = padding.pad(data); // PKCS#7 padded data. The length of 'padded' will be multiple of 16(blocksize)
        System.out.println(padded.length);
        System.out.println(padded.length % blocksize); // 0. Means everytime padded.length is multiple of blocksize
    }
}
```
