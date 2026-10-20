import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public class KeyDerivation {

    public static final int ROUNDS = 3;
    public static final int SALT_LEN = 16;
    public static final int NONCE_LEN = 16;
    public static final int TAG_LEN = 32;
    public static final byte VERSION = 2;
    private static final int ITERATIONS = 210_000;
    private static final SecureRandom RNG = new SecureRandom();

    // Two independent keys: one for encryption, one for authentication
    public static class Keys {
        public final byte[] encKey;
        public final byte[] macKey;
        Keys(byte[] encKey, byte[] macKey) {
            this.encKey = encKey;
            this.macKey = macKey;
        }
    }

    public static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    // Password + salt -> master key (PBKDF2) -> encKey and macKey
    public static Keys deriveKeys(char[] password, byte[] salt) throws GeneralSecurityException {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password must not be empty");
        }
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, 256);
        try {
            byte[] master = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
            byte[] enc = hmac(master, "WEAVE-ENC".getBytes(StandardCharsets.UTF_8));
            byte[] mac = hmac(master, "WEAVE-MAC".getBytes(StandardCharsets.UTF_8));
            return new Keys(enc, mac);
        } finally {
            spec.clearPassword();
        }
    }

    public static byte[] hmac(byte[] key, byte[]... parts) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        for (byte[] p : parts) {
            mac.update(p);
        }
        return mac.doFinal();
    }
}