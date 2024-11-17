package nsu.mikhalev.cryptographer;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class AESFileEncryptorTest {
    private static final int BLOCK_SIZE = 16;

    @Test
    public void testEncryption() {
        byte[] plaintext = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            plaintext[i] = (byte) (i + 1);
        }

        byte[] key = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            key[i] = (byte) (BLOCK_SIZE - i);
        }

        byte[] ciphertext = AESFileEncryptor.encrypt(plaintext, key);

        assertNotNull(ciphertext, "Шифрованный текст не должен быть null");
        assertEquals(plaintext.length, ciphertext.length, "Длина зашифрованного текста должна быть равна длине исходного текста");
        assertFalse(Arrays.equals(plaintext, ciphertext));
    }
}
