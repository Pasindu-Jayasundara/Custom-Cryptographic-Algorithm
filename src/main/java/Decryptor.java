import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

public class Decryptor {

    public String decrypt(String encoded, char[] password) throws GeneralSecurityException {
        byte[] raw = Base64.getDecoder().decode(encoded);
        int headerLen = 1 + KeyDerivation.SALT_LEN + KeyDerivation.NONCE_LEN;

        if (raw.length < headerLen + KeyDerivation.TAG_LEN || raw[0] != KeyDerivation.VERSION) {
            throw new GeneralSecurityException("Invalid or unsupported ciphertext");
        }

        byte[] header = Arrays.copyOfRange(raw, 0, headerLen);
        byte[] salt = Arrays.copyOfRange(raw, 1, 1 + KeyDerivation.SALT_LEN);
        byte[] nonce = Arrays.copyOfRange(raw, 1 + KeyDerivation.SALT_LEN, headerLen);
        byte[] data = Arrays.copyOfRange(raw, headerLen, raw.length - KeyDerivation.TAG_LEN);
        byte[] tag = Arrays.copyOfRange(raw, raw.length - KeyDerivation.TAG_LEN, raw.length);

        KeyDerivation.Keys keys = KeyDerivation.deriveKeys(password, salt);

        byte[] expected = KeyDerivation.hmac(keys.macKey, header, data);
        if (!MessageDigest.isEqual(expected, tag)) {
            throw new GeneralSecurityException("Authentication failed: wrong password or data was modified");
        }

        int n = data.length;
        for (int r = KeyDerivation.ROUNDS - 1; r >= 0; r--) {
            RoundParams p = new RoundParams(keys.encKey, nonce, r, n);

            byte[] unshuffled = new byte[n];
            for (int i = 0; i < n; i++) {
                unshuffled[p.perm[i]] = data[i];
            }
            data = unshuffled;

            for (int i = 0; i < n; i++) {
                int x = (data[i] & 0xFF) ^ p.k2[i];
                data[i] = (byte) ((x - p.k1[i]) & 0xFF);
            }
        }
        return new String(data, StandardCharsets.UTF_8);
    }
}