package kronaegit.crypto.checksum;

public class CRC32 implements Checksum {
    private final java.util.zip.CRC32 crc = new java.util.zip.CRC32();
    public byte[] generate(byte[] data) {
        synchronized (crc) {
            crc.reset();
            crc.update(data);
            long value = crc.getValue();
            return new byte[] {
                    (byte) (value >> 24),  // MSB
                    (byte) (value >> 16),
                    (byte) (value >> 8),
                    (byte) (value)         // LSB
            };
        }
    }
}
