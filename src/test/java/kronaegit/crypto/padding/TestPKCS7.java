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