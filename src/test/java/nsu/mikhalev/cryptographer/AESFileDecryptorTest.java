package nsu.mikhalev.cryptographer;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AESFileDecryptorTest {
    private static final byte[] ENCRYPTED_DATA = {
        (byte) 0x69, (byte) 0x8A, (byte) 0x56, (byte) 0xED, (byte) 0x6B, (byte) 0xC8, (byte) 0x12, (byte) 0x2C,
        (byte) 0x99, (byte) 0xA0, (byte) 0xDB, (byte) 0x51, (byte) 0xD5, (byte) 0xC1, (byte) 0x1D, (byte) 0xC2
    };
    private static final byte[] KEY = {
        (byte) 0x2b, (byte) 0x7e, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
        (byte) 0xab, (byte) 0xf7, (byte) 0x97, (byte) 0x75, (byte) 0x46, (byte) 0x1f, (byte) 0x23, (byte) 0x56
    };

    @Test
    @DisplayName("Проверка дешифрования 16-байтовых данных")
    public void testDecrypt() {
        byte[] expectedDecryptedData = {
            (byte) 0x32, (byte) 0x88, (byte) 0x31, (byte) 0xe0, (byte) 0x43, (byte) 0x5a, (byte) 0x31, (byte) 0x37,
            (byte) 0xf6, (byte) 0x30, (byte) 0x98, (byte) 0x07, (byte) 0xa8, (byte) 0x8d, (byte) 0xa2, (byte) 0x34
        };

        byte[] decryptedData = AESFileDecryptor.decrypt(ENCRYPTED_DATA, KEY);
        assertArrayEquals(expectedDecryptedData, decryptedData);
    }
}
