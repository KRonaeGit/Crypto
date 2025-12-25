package kronaegit.crypto.padding;

public abstract class Padding {
    private final int blockSize;

    public Padding(int blockSize) {
        this.blockSize = blockSize;
    }

    public int getBlockSize() {
        return blockSize;
    }

    public abstract byte[] pad(byte[] data);
    public abstract byte[] unpad(byte[] padded);
}
