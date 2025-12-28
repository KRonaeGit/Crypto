package kronaegit.crypto.hash;

import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import java.security.GeneralSecurityException;
import java.util.Arrays;

    public interface PasswordHash<R, H> {
    @Contract(value = "_ -> new", pure = true)
    static @NotNull PasswordHash<byte[], byte[]> of(Hash hash) {
        return new PasswordHash<byte[], byte[]>() {
            @Override
            public byte @NotNull [] hashpw(byte @NotNull [] raw) {
                return hash.hash(raw);
            }

            @Override
            public boolean checkpw(byte @NotNull [] raw, byte @NotNull [] hash) throws GeneralSecurityException {
                return Arrays.equals(hashpw(raw), hash);
            }
        };
    }

    @NotNull H hashpw(@NotNull R raw) throws GeneralSecurityException;
    boolean checkpw(@NotNull R raw, @NotNull H hash) throws GeneralSecurityException;
}
