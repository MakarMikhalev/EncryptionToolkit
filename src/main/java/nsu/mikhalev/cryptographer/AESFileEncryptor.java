package nsu.mikhalev.cryptographer;

import lombok.experimental.UtilityClass;

import java.util.Arrays;

@UtilityClass
public class AESFileEncryptor {
    private static final int BLOCK_SIZE = 16;
    private static final int[] S_BOX = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
    };

    public static byte[] encrypt(byte[] plaintext, byte[] key) {
        if (plaintext.length != BLOCK_SIZE || key.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("Длина блока и ключа должны быть равны 16 байтам");
        }

        byte[] state = Arrays.copyOf(plaintext, BLOCK_SIZE);
        byte[][] roundKeys = keyExpansion(key);

        addRoundKey(state, roundKeys[0]);
        for (int round = 1; round <= 9; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, roundKeys[round]);
        }
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, roundKeys[10]);

        return state;
    }

    private static void subBytes(byte[] state) {
        for (int i = 0; i < state.length; i++) {
            int index = state[i] & 0xFF;
            if (index < 16) {
                state[i] = (byte) (S_BOX[index]);
            }
        }
    }

    private static void shiftRows(byte[] state) {
        byte[] temp = Arrays.copyOf(state, BLOCK_SIZE);
        state[1] = temp[5];
        state[5] = temp[9];
        state[9] = temp[13];
        state[13] = temp[1];
    }

    private static void mixColumns(byte[] state) {
        for (int i = 0; i < 4; i++) {
            int col = i * 4;

            int t0 = state[col] ^ state[col + 1];
            int t1 = state[col + 2] ^ state[col + 3];
            state[col] ^= t0;
            state[col + 1] ^= t1;
        }
    }

    private static void addRoundKey(byte[] state, byte[] roundKey) {
        for (int i = 0; i < state.length; i++) {
            state[i] ^= roundKey[i];
        }
    }

    private static byte[][] keyExpansion(byte[] key) {
        byte[][] roundKeys = new byte[11][BLOCK_SIZE];
        System.arraycopy(key, 0, roundKeys[0], 0, BLOCK_SIZE);

        for (int i = 1; i < roundKeys.length; i++) {
            byte[] temp = Arrays.copyOf(roundKeys[i - 1], BLOCK_SIZE);

            for (int j = 0; j < BLOCK_SIZE; j++) {
                roundKeys[i][j] = (byte) (roundKeys[i - 1][j] ^ temp[j]);
            }
        }
        return roundKeys;
    }
}
