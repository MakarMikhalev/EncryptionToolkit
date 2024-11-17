package nsu.mikhalev.cryptographer;

import lombok.experimental.UtilityClass;

@UtilityClass
public class StreamCipher {
    private static final int a = 5;
    private static final int b = 12;
    private static final int c = 23;

    public int[] encrypt(String message, int seed) {
        int state = seed;
        var encrypt = new int[message.length()];
        for (int i = 0; i < message.length(); ++i) {
            state = nextKey(state);
            encrypt[i] = message.charAt(i) ^ state;
        }
        return encrypt;
    }

    public String decrypt(int[] encrypt, int seed) {
        var decrypt = new StringBuilder();
        int state = seed;
        for (int v : encrypt) {
            state = nextKey(state);
            decrypt.append((char) (v ^ state));
        }
        return decrypt.toString();
    }

    private int nextKey(int v) {
        return (a * v + b) % c;
    }
}
