package com.virustotal.yara;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static com.virustotal.yara.yara_h.C_POINTER;
import static com.virustotal.yara.yara_h.ERROR_SUCCESS;
import static com.virustotal.yara.yara_h_1.*;
import static com.virustotal.yara.yara_h_2.YR_VERSION;

public class YaraJavaTests {
    public static final int NULL_CHAR = 1;

    @BeforeAll
    public static void init(){
        yr_initialize();
    }

    @Test
    public void testYaraVersion(){
        ByteBuffer versionBuffer = YR_VERSION().asByteBuffer();
        byte[] versionBytes = new byte[versionBuffer.remaining() - NULL_CHAR];
        versionBuffer.get(versionBytes);

        String versionString = new String(versionBytes, StandardCharsets.UTF_8);

        Assertions.assertNotNull(versionString);
        Assertions.assertFalse(versionString.isEmpty());
        Assertions.assertEquals("4.2.3", versionString);
    }

    @Test
    public void testYaraCompilerCreateAndDestroy() {
        try (Arena arena = Arena.openConfined()) {
            MemorySegment compilerAddress = arena.allocate(C_POINTER); // YR_COMPILER**
            int created = yr_compiler_create(compilerAddress);

            Assertions.assertEquals(ERROR_SUCCESS(), created);

            MemorySegment compiler = compilerAddress.get(C_POINTER, 0); // YR_COMPILER*
            yr_compiler_destroy(compiler);
        }
    }

    @AfterAll
    public static void finish(){
        yr_finalize();
    }
}
