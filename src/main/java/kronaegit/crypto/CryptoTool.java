package kronaegit.crypto;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class CryptoTool {
    private CryptoTool() {}
    public static String toHex(byte @NotNull [] bytes, boolean upperCase) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes)
            sb.append(String.format("%02x", b));
        if(upperCase) return sb.toString().toUpperCase();
        return sb.toString().toLowerCase();
    }
    public static String toHex(byte[] bytes) {
        return toHex(bytes, false);
    }
    public static byte @NotNull [] hexTo(@NotNull String hex) {
        int length = hex.length();
        if (length % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have an even length.");
        }
        byte[] bytes = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            int byteValue = Integer.parseInt(hex.substring(i, i + 2), 16);
            bytes[i / 2] = (byte) byteValue;
        }
        return bytes;
    }


    public static @NotNull SecureRandom random() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException ignored) { }

        try {
            return SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            // If no secure random algorithm is available, it's better to fail than to use an insecure one.
            throw new RuntimeException("No secure random algorithm available.", e);
        }
    }
    public static @NotNull SecureRandom random(@Nullable SecureRandom random) {
        if (random != null)
            return random;
        return random();
    }
    public static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
