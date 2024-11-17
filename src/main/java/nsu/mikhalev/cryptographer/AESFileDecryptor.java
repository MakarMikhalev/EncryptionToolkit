package nsu.mikhalev.cryptographer;

import java.util.Arrays;

public class AESFileDecryptor {

    private static final int[] INVERSE_S_BOX = {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, 0x7C,
        0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D,
        0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x90, 0x3E, 0xB9,
        0xAB, 0xE1, 0x2F, 0x75, 0x62, 0x9D, 0x93, 0x58, 0x1F, 0x94, 0xF5, 0x8A, 0x48, 0x30, 0x06, 0x56, 0xE3
    };


    private static byte[] inverseShiftRows(byte[] block) {
        byte[] newBlock = new byte[block.length];
        for (int i = 0; i < 4; i++) {
            System.arraycopy(block, i * 4, newBlock, (i + 4 - i) % 4 * 4, 4);
        }
        return newBlock;
    }

    private static byte[] inverseSubBytes(byte[] block) {
        byte[] newBlock = new byte[block.length];
        for (int i = 0; i < block.length; i++) {
            newBlock[i] = (byte) INVERSE_S_BOX[block[i] & 0xFF];
        }
        return newBlock;
    }

    private static byte[] addRoundKey(byte[] block, byte[] roundKey) {
        for (int i = 0; i < 16; i++) {
            block[i] ^= roundKey[i];
        }
        return block;
    }

    private static int multiply(int x, int y) {
        int result = 0;
        while (x != 0) {
            if ((x & 1) != 0) {
                result ^= y;
            }
            x >>= 1;
        }
        return result;
    }

    public static byte[] inverseMixColumns(byte[] block) {
        byte[] result = new byte[16];

        for (int i = 0; i < 4; i++) {
            int[] column = new int[4];
            for (int j = 0; j < 4; j++) {
                column[j] = block[i + j * 4] & 0xFF;
            }

            result[i] = (byte) (multiply(column[0], 0x0e) ^ multiply(column[1], 0x0b) ^ multiply(column[2], 0x0d) ^ multiply(column[3], 0x09));
            result[i + 4] = (byte) (multiply(column[0], 0x09) ^ multiply(column[1], 0x0e) ^ multiply(column[2], 0x0b) ^ multiply(column[3], 0x0d));
            result[i + 8] = (byte) (multiply(column[0], 0x0d) ^ multiply(column[1], 0x09) ^ multiply(column[2], 0x0e) ^ multiply(column[3], 0x0b));
            result[i + 12] = (byte) (multiply(column[0], 0x0b) ^ multiply(column[1], 0x0d) ^ multiply(column[2], 0x09) ^ multiply(column[3], 0x0e));
        }

        return result;
    }

    public static byte[] decrypt(byte[] encryptedData, byte[] key) {
        byte[] block = encryptedData;
        block = addRoundKey(block, key);

        for (int round = 9; round >= 0; round--) {
            block = inverseShiftRows(block);
            block = inverseSubBytes(block);
            block = inverseMixColumns(block);

            byte[] roundKey = Arrays.copyOfRange(key, round * 16, (round + 1) * 16);
            block = addRoundKey(block, roundKey);
        }

        return block;
    }
}
