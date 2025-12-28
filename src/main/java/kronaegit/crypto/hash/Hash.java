package kronaegit.crypto.hash;

import kronaegit.crypto.CryptoTool;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public interface Hash {
    byte[] hash(byte[] data);
    default byte[] hash(@NotNull String str, Charset charset) {
        return hash(str.getBytes(charset));
    }
    default byte[] hash(String str) {
        return hash(str, StandardCharsets.UTF_8);
    }
    default String hashToString(byte[] data, boolean upperCase) {
        return CryptoTool.toHex(hash(data), upperCase);
    }
    default String hashToString(byte[] data) {
        return CryptoTool.toHex(data);
    }
    default String hashToString(@NotNull String str, Charset charset, boolean upperCase) {
        return hashToString(str.getBytes(charset), upperCase);
    }
    default String hashToString(String str, Charset charset) {
        return hashToString(str, charset, false);
    }
    default String hashToString(String str, boolean upperCase) {
        return hashToString(str, StandardCharsets.UTF_8, upperCase);
    }
    default String hashToString(String str) {
        return hashToString(str, false);
    }

    int getResultSize();
    int getInternalBlockSize();
}
