package com.virustotal.yara;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static com.virustotal.yara.yara_h_1.yr_initialize;
import static com.virustotal.yara.yara_h_1.yr_finalize;
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

    @AfterAll
    public static void finish(){
        yr_finalize();
    }
}
