package com.virustotal.yara;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static com.virustotal.yara.yara_h.C_POINTER;
import static com.virustotal.yara.yara_h.ERROR_SUCCESS;
import static com.virustotal.yara.yara_h_1.*;
import static com.virustotal.yara.yara_h_2.YR_VERSION;

public class YaraJavaTests {
    public static final int NULL_CHAR = 1;
    public static final int ZERO_ERRORS = 0;

    private static final Path YARA_RULES_SOURCE_DOC_DIR = Paths.get("src","test","resources", "yara", "rules", "source", "doc");
    private static final Path YARA_RULES_BIN_DOC_DIR = Paths.get("src","test","resources", "yara", "rules", "bin", "doc");

    @BeforeAll
    public static void init() {
        int initialized = yr_initialize();
        Assertions.assertEquals(ERROR_SUCCESS(), initialized);
    }

    @Test
    public void testYaraVersion() {
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

    @Test
    public void testYaraCompilerAddString() {
        try (Arena arena = Arena.openConfined()) {
            MemorySegment compilerAddress = arena.allocate(C_POINTER); // YR_COMPILER**
            int created = yr_compiler_create(compilerAddress);
            Assertions.assertEquals(ERROR_SUCCESS(), created);
            MemorySegment compiler = compilerAddress.get(C_POINTER, 0); // YR_COMPILER*

            File yaraDocRulesDir = YARA_RULES_SOURCE_DOC_DIR.toFile();
            yaraDocRulesDir.mkdirs();

            File[] yaraFiles = yaraDocRulesDir.listFiles((dir, name) -> name.endsWith(".yara"));

            Assertions.assertNotNull(yaraFiles);
            Assertions.assertTrue(yaraFiles.length > 0);

            MemorySegment namespaceSegment = arena.allocateUtf8String("doc");  // char*

            for (File rule : yaraFiles) {
                try {
                    String ruleString = Files.readString(rule.toPath());
                    MemorySegment ruleStringSegment = arena.allocateUtf8String(ruleString); // char*

                    int compilationErrors = yr_compiler_add_string(compiler, ruleStringSegment, namespaceSegment);
                    Assertions.assertEquals(ZERO_ERRORS, compilationErrors);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }

            yr_compiler_destroy(compiler);
        }
    }

    @Test
    public void testYaraCompilerGetSaveAndDestroyRules(){
        try (Arena arena = Arena.openConfined()) {
            MemorySegment compilerAddress = arena.allocate(C_POINTER); // YR_COMPILER**
            int created = yr_compiler_create(compilerAddress);
            Assertions.assertEquals(ERROR_SUCCESS(), created);
            MemorySegment compiler = compilerAddress.get(C_POINTER, 0); // YR_COMPILER*

            File yaraDocRulesDir = YARA_RULES_SOURCE_DOC_DIR.toFile();
            yaraDocRulesDir.mkdirs();
            Assertions.assertTrue(YARA_RULES_BIN_DOC_DIR.toFile().exists());

            File[] yaraFiles = yaraDocRulesDir.listFiles((dir, name) -> name.endsWith(".yara"));

            Assertions.assertNotNull(yaraFiles);
            Assertions.assertTrue(yaraFiles.length > 0);

            MemorySegment namespaceSegment = arena.allocateUtf8String("doc");  // char*

            for (File rule : yaraFiles) {
                try {
                    String ruleString = Files.readString(rule.toPath());
                    MemorySegment ruleStringSegment = arena.allocateUtf8String(ruleString); // char*

                    int compilationErrors = yr_compiler_add_string(compiler, ruleStringSegment, namespaceSegment);
                    Assertions.assertEquals(ZERO_ERRORS, compilationErrors);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }

            MemorySegment yaraRulesAddress = arena.allocate(C_POINTER); // YR_RULES**

            int rulesResult = yr_compiler_get_rules(compiler, yaraRulesAddress);
            Assertions.assertEquals(ERROR_SUCCESS(), rulesResult);

            MemorySegment yaraRules = yaraRulesAddress.get(C_POINTER, 0); // YR_RULES*

            YARA_RULES_BIN_DOC_DIR.toFile().mkdirs();
            Assertions.assertTrue(YARA_RULES_BIN_DOC_DIR.toFile().exists());

            MemorySegment compiledRulesFilename = arena.allocateUtf8String(YARA_RULES_BIN_DOC_DIR + "/yara-rules.yara.bin"); // char*

            int rulesSaved = yr_rules_save(yaraRules, compiledRulesFilename);
            Assertions.assertEquals(ERROR_SUCCESS(), rulesSaved);

            int rulesDestroyed = yr_rules_destroy(yaraRules);
            Assertions.assertEquals(ERROR_SUCCESS(), rulesDestroyed);

            yr_compiler_destroy(compiler);
        }
    }

    @AfterAll
    public static void finish() {
        int finalized = yr_finalize();
        Assertions.assertEquals(ERROR_SUCCESS(), finalized);
    }
}
