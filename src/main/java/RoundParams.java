// Everything one round needs. Encryption and decryption build it identically.
public class RoundParams {

    public final int[] k1;    // substitution key bytes
    public final int[] k2;    // XOR key bytes
    public final int[] perm;  // transposition permutation

    public RoundParams(byte[] encKey, byte[] nonce, int round, int n) {
        KeyStream ks = new KeyStream(encKey, nonce, round);

        k1 = new int[n];
        k2 = new int[n];
        for (int i = 0; i < n; i++) {
            k1[i] = ks.nextByte();
            k2[i] = ks.nextByte();
        }

        perm = new int[n];
        for (int i = 0; i < n; i++) {
            perm[i] = i;
        }
        // Fisher-Yates shuffle driven by the key stream
        for (int i = n - 1; i > 0; i--) {
            int j = ks.nextInt(i + 1);
            int t = perm[i];
            perm[i] = perm[j];
            perm[j] = t;
        }
    }
} public class RoundParams {
}
