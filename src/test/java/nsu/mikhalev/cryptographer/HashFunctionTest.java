package nsu.mikhalev.cryptographer;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class HashFunctionTest {

    @Test
    public void testHashFunction() {
        byte[] input = "hello".getBytes();
        byte[] expectedHash = new byte[]{-32, -67, 103, -42};

        byte[] hashResult = HashFunction.hash(input);

        assertArrayEquals(expectedHash, hashResult);
    }

    @Test
    public void testEmptyInput() {
        byte[] input = new byte[]{};
        byte[] expectedHash = new byte[]{0x00, 0x00, 0x00, 0x00};

        byte[] hashResult = HashFunction.hash(input);

        assertArrayEquals(expectedHash, hashResult);
    }
}
