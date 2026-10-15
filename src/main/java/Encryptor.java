import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

public class Encryptor {

    public String encrypt(String plaintext, char[] password) throws GeneralSecurityException {
        byte[] salt = KeyDerivation.randomBytes(KeyDerivation.SALT_LEN);
        byte[] nonce = KeyDerivation.randomBytes(KeyDerivation.NONCE_LEN);
        KeyDerivation.Keys keys = KeyDerivation.deriveKeys(password, salt);

        byte[] data = plaintext.getBytes(StandardCharsets.UTF_8);
        int n = data.length;

        for (int r = 0; r < KeyDerivation.ROUNDS; r++) {
            RoundParams p = new RoundParams(keys.encKey, nonce, r, n);

            // Step 1 and 2: substitution (add), then XOR
            for (int i = 0; i < n; i++) {
                int x = ((data[i] & 0xFF) + p.k1[i]) & 0xFF;
                data[i] = (byte) (x ^ p.k2[i]);
            }

            // Step 3: transposition (shuffle positions)
            byte[] shuffled = new byte[n];
            for (int i = 0; i < n; i++) {
                shuffled[i] = data[p.perm[i]];
            }
            data = shuffled;
        }

        // Step 4: authenticate (encrypt-then-MAC) over header + ciphertext
        byte[] header = ByteBuffer.allocate(1 + KeyDerivation.SALT_LEN + KeyDerivation.NONCE_LEN)
                .put(KeyDerivation.VERSION).put(salt).put(nonce).array();
        byte[] tag = KeyDerivation.hmac(keys.macKey, header, data);

        byte[] out = ByteBuffer.allocate(header.length + n + tag.length)
                .put(header).put(data).put(tag).array();
        return Base64.getEncoder().encodeToString(out);
    }
}