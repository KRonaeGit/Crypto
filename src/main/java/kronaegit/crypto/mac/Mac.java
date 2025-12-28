package kronaegit.crypto.mac;

import kronaegit.crypto.CryptoTool;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

public abstract class Mac<K> {
    private final K keyObject;
    private final byte[] keyBytes;
    public Mac(byte[] key, Object... data) {
        this.keyBytes = key;
        this.keyObject = generateKeyObject(key, data);
    }

    protected abstract K generateKeyObject(byte[] key, Object... data);

    public K getKeyObject() {
        return keyObject;
    }
    public byte[] getKeyBytes() {
        return keyBytes;
    }

    public abstract byte[] generateMac(byte[] data) throws GeneralSecurityException;
    public byte[] generateMac(@NotNull String str, Charset charset) throws GeneralSecurityException {
        return generateMac(str.getBytes(charset));
    }
    public byte[] generateMac(String str) throws GeneralSecurityException {
        return generateMac(str, StandardCharsets.UTF_8);
    }
    public String generateMacString(byte[] data, boolean upperCase) throws GeneralSecurityException {
        return CryptoTool.toHex(generateMac(data), upperCase);
    }
    public String generateMacString(byte[] data) throws GeneralSecurityException {
        return generateMacString(data, false);
    }
    public String generateMacString(@NotNull String str, Charset charset, boolean upperCase) throws GeneralSecurityException {
        return generateMacString(str.getBytes(charset), upperCase);
    }
    public String generateMacString(String str, Charset charset) throws GeneralSecurityException {
        return generateMacString(str, charset, false);
    }
    public String generateMacString(String str, boolean upperCase) throws GeneralSecurityException {
        return generateMacString(str, StandardCharsets.UTF_8, upperCase);
    }
    public String generateMacString(String str) throws GeneralSecurityException {
        return generateMacString(str, false);
    }

    public boolean verifyMac(byte[] data, byte[] mac) throws GeneralSecurityException {
        byte[] computedMac = generateMac(data);
        return MessageDigest.isEqual(computedMac, mac);
    }
    public boolean verifyMac(String str, byte[] mac) throws GeneralSecurityException {
        byte[] computedMac = generateMac(str);
        return MessageDigest.isEqual(computedMac, mac);
    }
    public boolean verifyMac(byte[] data, String macString) throws GeneralSecurityException {
        byte[] computedMac = generateMac(data);
        return MessageDigest.isEqual(computedMac, CryptoTool.hexTo(macString));
    }
    public boolean verifyMac(String str, String macString) throws GeneralSecurityException {
        byte[] computedMac = generateMac(str);
        return MessageDigest.isEqual(computedMac, CryptoTool.hexTo(macString));
    }
}
