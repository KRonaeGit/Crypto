package kronaegit.crypto.cipher;

import org.jetbrains.annotations.NotNull;

import java.security.GeneralSecurityException;
import java.util.Objects;

public abstract class Key<K> {
    private final K key;

    public Key(byte[] key) throws GeneralSecurityException {
        this.key = generateKeyObject(key);
    }

    protected abstract @NotNull K generateKeyObject(byte[] key) throws GeneralSecurityException;

    public @NotNull K getKey() {
        return key;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Key<?> key1 = (Key<?>) o;
        return Objects.equals(key, key1.key);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(key);
    }
}
