package nsu.mikhalev.cryptographer;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("Тесты поточного шифра для шифрования/расшифрования строки")
class StreamCipherTest {

    @ParameterizedTest
    @CsvSource({
        "'Hello, World!', 42",
        "'1234567890!@#$%^&*()', 15",
        "'Привет, мир! 🌍', 99"
    })
    @DisplayName("Шифрование и расшифровка строки")
    void testEncryptDecrypt(String message, int seed) {
        int[] encrypted = StreamCipher.encrypt(message, seed);

        Assertions.assertEquals(message.length(), encrypted.length, "Длина зашифрованного сообщения должна совпадать с оригиналом");

        String decrypted = StreamCipher.decrypt(encrypted, seed);
        Assertions.assertEquals(message, decrypted, "Расшифрованное сообщение должно совпадать с оригиналом");
    }

    @ParameterizedTest
    @DisplayName("Шифрование и расшифровка пустой строки")
    @ValueSource(ints = {0, 42, 99})
    void testEmptyMessage(int seed) {
        String message = "";

        int[] encrypted = StreamCipher.encrypt(message, seed);
        Assertions.assertNotNull(encrypted, "Зашифрованное сообщение не должно быть null");
        Assertions.assertEquals(0, encrypted.length, "Длина зашифрованного сообщения должна быть 0 для пустого входа");

        String decrypted = StreamCipher.decrypt(encrypted, seed);
        Assertions.assertEquals(message, decrypted, "Расшифрованное сообщение должно совпадать с оригиналом");
    }

    @ParameterizedTest
    @CsvSource({
        "'~!@#$%^&*()_+-=[]{}|;', 12",
        "'\\t\\n\\r\\f\\b', 7"
    })
    @DisplayName("Шифрование и расшифровка специальных символов")
    void testSpecialCharacters(String message, int seed) {
        int[] encrypted = StreamCipher.encrypt(message, seed);
        Assertions.assertEquals(message.length(), encrypted.length, "Длина зашифрованного сообщения должна совпадать с оригиналом");

        String decrypted = StreamCipher.decrypt(encrypted, seed);
        Assertions.assertEquals(message, decrypted, "Расшифрованное сообщение должно совпадать с оригиналом");
    }
}
