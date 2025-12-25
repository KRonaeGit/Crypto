package kronaegit.crypto.checksum;

public class Adler32 implements Checksum {
    private final java.util.zip.Adler32 adler = new java.util.zip.Adler32();

    public byte[] generate(byte[] data) {
        synchronized (adler) {
            adler.reset();
            adler.update(data);
            long value = adler.getValue();

            return new byte[]{
                    (byte) (value >> 24),  // MSB
                    (byte) (value >> 16),
                    (byte) (value >> 8),
                    (byte) (value)         // LSB
            };
        }
    }
}
