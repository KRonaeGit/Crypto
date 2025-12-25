package kronaegit.crypto.padding;

import java.security.SecureRandom;
import java.util.Arrays;

public class PKCS1Padding extends Padding {
    // !null: toencrypt (random, block type 0x02) | null: tosign (absolute, block type 0x01)
    private final SecureRandom random;

    /**
     * Padding to sign
     */
    public PKCS1Padding(int blockSize) {
        super(blockSize);
        this.random = null;
    }

    /**
     * Padding to encrypt
     */
    public PKCS1Padding(int blockSize, SecureRandom random) {
        super(blockSize);
        this.random = random;
    }

    public byte[] pad(byte[] data) {
        int dataLength = data.length;
        if (dataLength > getBlockSize() - 11) {
            throw new IllegalArgumentException("Data is too long for the given block size.");
        }
        int paddingLength = getBlockSize() - 3 - dataLength;
        byte[] padding = new byte[paddingLength];

        if (random != null) {
            for (int i = 0; i < paddingLength; i++) {
                byte r;
                do {
                    r = (byte) random.nextInt(256);
                } while (r == 0);
                padding[i] = r;
            }
        } else {
            Arrays.fill(padding, (byte) 0xFF);
        }

        byte[] padded = new byte[getBlockSize()];
        padded[0] = 0x00;
        padded[1] = random == null ? (byte) 0x01 : (byte) 0x02;
        System.arraycopy(padding, 0, padded, 2, padding.length);
        padded[2 + padding.length] = 0x00;
        System.arraycopy(data, 0, padded, 2 + padding.length + 1, dataLength);
        return padded;
    }

    public byte[] unpad(byte[] data) {
        String errorMessage = "Invalid PKCS#1 padding.";
        if (data.length != getBlockSize() || data[0] != 0x00) {
            throw new IllegalArgumentException(errorMessage);
        }
        byte blockType = data[1];
        if (blockType != 0x02 && blockType != 0x01) {
            throw new IllegalArgumentException(errorMessage);
        }
        if (blockType != (random == null ? (byte) 0x01 : (byte) 0x02)) {
            throw new IllegalArgumentException(errorMessage);
        }

        int index = 2;
        if (random == null) { // Block type 0x01 (sign)
            while (index < data.length && data[index] != 0x00) {
                if (data[index] != (byte) 0xFF) {
                    throw new IllegalArgumentException(errorMessage);
                }
                index++;
            }
        } else { // Block type 0x02 (encrypt)
            while (index < data.length && data[index] != 0x00) {
                index++;
            }
        }
        if (index == data.length || index < 10) { // Padding string must be at least 8 bytes long
            throw new IllegalArgumentException(errorMessage);
        }
        byte[] unpadded = new byte[data.length - index - 1];
        System.arraycopy(data, index + 1, unpadded, 0, unpadded.length);
        return unpadded;
    }
}
