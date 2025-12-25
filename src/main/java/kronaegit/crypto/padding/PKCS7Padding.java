package kronaegit.crypto.padding;

import java.util.Arrays;

public class PKCS7Padding extends Padding {
    public PKCS7Padding(int blockSize) {
        super(blockSize);
    }

    public byte[] pad(byte[] data) {
        int padLen = getBlockSize() - (data.length % getBlockSize());
        byte[] padded = Arrays.copyOf(data, data.length + padLen);
        Arrays.fill(padded, data.length, padded.length, (byte) padLen);
        return padded;
    }

    public byte[] unpad(byte[] data) {
        int padLen = data[data.length - 1] & 0xFF;

        if (padLen < 1 || padLen > getBlockSize()) {
            throw new IllegalArgumentException("Invalid padding.");
        }

        for (int i = data.length - padLen; i < data.length; i++) {
            if (data[i] != (byte) padLen) {
                throw new IllegalArgumentException("Invalid padding.");
            }
        }

        return Arrays.copyOfRange(data, 0, data.length - padLen);
    }
}
