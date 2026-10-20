import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

// Cryptographic key stream: HMAC-SHA256(key, nonce || round || counter)
public class KeyStream {

    private final Mac mac;
    private final byte[] nonce;
    private final int round;
    private long counter = 0;
    private byte[] block = new byte[0];
    private int pos = 0;

    public KeyStream(byte[] encKey, byte[] nonce, int round) {
        try {
            this.mac = Mac.getInstance("HmacSHA256");
            this.mac.init(new SecretKeySpec(encKey, "HmacSHA256"));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        this.nonce = nonce;
        this.round = round;
    }

    private void refill() {
        mac.update(nonce);
        mac.update(ByteBuffer.allocate(12).putInt(round).putLong(counter++).array());
        block = mac.doFinal();
        pos = 0;
    }

    // Returns a key byte in the range 0-255
    public int nextByte() {
        if (pos >= block.length) refill();
        return block[pos++] & 0xFF;
    }

    // Unbiased number in the range 0 to bound-1 (rejection sampling)
    public int nextInt(int bound) {
        long range = 1L << 32;
        long limit = range - (range % bound);
        long v;
        do {
            v = 0;
            for (int i = 0; i < 4; i++) {
                v = (v << 8) | nextByte();
            }
        } while (v >= limit);
        return (int) (v % bound);
    }
}