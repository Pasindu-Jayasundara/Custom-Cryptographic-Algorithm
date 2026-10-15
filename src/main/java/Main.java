import java.util.Base64;

public class Main {

    public static void main(String[] args) throws Exception {
        char[] password = "MySecretKey2026!".toCharArray();
        Encryptor enc = new Encryptor();
        Decryptor dec = new Decryptor();

        // Test 1: round trip
        String msg = "Meet me at 5pm near the library. 12345 @#$";
        String c1 = enc.encrypt(msg, password);
        System.out.println("Plaintext : " + msg);
        System.out.println("Ciphertext: " + c1);
        System.out.println("Decrypted : " + dec.decrypt(c1, password));
        System.out.println("Match     : " + msg.equals(dec.decrypt(c1, password)));
        System.out.println("-------------------------------------");

        // Test 2: same message encrypted twice gives different ciphertext
        String c2 = enc.encrypt(msg, password);
        System.out.println("Same message, different ciphertext: " + !c1.equals(c2));

        // Test 3: tampering is detected
        byte[] raw = Base64.getDecoder().decode(c1);
        raw[raw.length - 40] ^= 1;   // flip one bit inside the ciphertext
        try {
            dec.decrypt(Base64.getEncoder().encodeToString(raw), password);
            System.out.println("Tamper test: FAILED (not detected)");
        } catch (Exception e) {
            System.out.println("Tamper test: detected -> " + e.getMessage());
        }

        // Test 4: wrong password is rejected
        try {
            dec.decrypt(c1, "WrongPassword".toCharArray());
            System.out.println("Wrong password test: FAILED");
        } catch (Exception e) {
            System.out.println("Wrong password test: rejected -> " + e.getMessage());
        }

        // Test 5: empty and unicode messages
        for (String m : new String[] {"", "සුභ දවසක්! 你好 🔐"}) {
            System.out.println("Edge case OK: " + m.equals(dec.decrypt(enc.encrypt(m, password), password)));
        }
    }
}