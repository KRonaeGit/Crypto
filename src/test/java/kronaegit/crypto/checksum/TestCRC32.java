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