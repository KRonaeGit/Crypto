package kronaegit.crypto.checksum;

import java.util.Arrays;

public interface Checksum {
    byte[] generate(byte[] data);
    default boolean verify(byte[] data, byte[] checksum) {
        byte[] checksum2 = generate(data);
        return Arrays.equals(checksum2, checksum);
    }
}
