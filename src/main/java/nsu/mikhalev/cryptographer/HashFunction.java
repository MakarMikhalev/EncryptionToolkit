package nsu.mikhalev.cryptographer;

public class HashFunction {
    public static byte[] hash(byte[] input) {
        int hash = 0;

        for (int i = 0; i < input.length; i++) {
            hash ^= input[i];
            hash = (hash << 5) | (hash >>> 27);
        }

        return new byte[] {
            (byte) (hash & 0xFF),
            (byte) ((hash >> 8) & 0xFF),
            (byte) ((hash >> 16) & 0xFF),
            (byte) ((hash >> 24) & 0xFF)
        };
    }
}
