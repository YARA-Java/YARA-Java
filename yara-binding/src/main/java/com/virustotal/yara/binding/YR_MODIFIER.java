// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
/**
 * {@snippet :
 * struct YR_MODIFIER {
 *     int32_t flags;
 *     uint8_t xor_min;
 *     uint8_t xor_max;
 *     SIZED_STRING* alphabet;
 * };
 * }
 */
public class YR_MODIFIER {

    static final StructLayout $struct$LAYOUT = MemoryLayout.structLayout(
        Constants$root.C_INT$LAYOUT.withName("flags"),
        Constants$root.C_CHAR$LAYOUT.withName("xor_min"),
        Constants$root.C_CHAR$LAYOUT.withName("xor_max"),
        MemoryLayout.paddingLayout(16),
        Constants$root.C_POINTER$LAYOUT.withName("alphabet")
    ).withName("YR_MODIFIER");
    public static MemoryLayout $LAYOUT() {
        return YR_MODIFIER.$struct$LAYOUT;
    }
    static final VarHandle flags$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("flags"));
    public static VarHandle flags$VH() {
        return YR_MODIFIER.flags$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int32_t flags;
     * }
     */
    public static int flags$get(MemorySegment seg) {
        return (int)YR_MODIFIER.flags$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int32_t flags;
     * }
     */
    public static void flags$set(MemorySegment seg, int x) {
        YR_MODIFIER.flags$VH.set(seg, x);
    }
    public static int flags$get(MemorySegment seg, long index) {
        return (int)YR_MODIFIER.flags$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void flags$set(MemorySegment seg, long index, int x) {
        YR_MODIFIER.flags$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle xor_min$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("xor_min"));
    public static VarHandle xor_min$VH() {
        return YR_MODIFIER.xor_min$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * uint8_t xor_min;
     * }
     */
    public static byte xor_min$get(MemorySegment seg) {
        return (byte)YR_MODIFIER.xor_min$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * uint8_t xor_min;
     * }
     */
    public static void xor_min$set(MemorySegment seg, byte x) {
        YR_MODIFIER.xor_min$VH.set(seg, x);
    }
    public static byte xor_min$get(MemorySegment seg, long index) {
        return (byte)YR_MODIFIER.xor_min$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void xor_min$set(MemorySegment seg, long index, byte x) {
        YR_MODIFIER.xor_min$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle xor_max$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("xor_max"));
    public static VarHandle xor_max$VH() {
        return YR_MODIFIER.xor_max$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * uint8_t xor_max;
     * }
     */
    public static byte xor_max$get(MemorySegment seg) {
        return (byte)YR_MODIFIER.xor_max$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * uint8_t xor_max;
     * }
     */
    public static void xor_max$set(MemorySegment seg, byte x) {
        YR_MODIFIER.xor_max$VH.set(seg, x);
    }
    public static byte xor_max$get(MemorySegment seg, long index) {
        return (byte)YR_MODIFIER.xor_max$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void xor_max$set(MemorySegment seg, long index, byte x) {
        YR_MODIFIER.xor_max$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle alphabet$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("alphabet"));
    public static VarHandle alphabet$VH() {
        return YR_MODIFIER.alphabet$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * SIZED_STRING* alphabet;
     * }
     */
    public static MemorySegment alphabet$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)YR_MODIFIER.alphabet$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * SIZED_STRING* alphabet;
     * }
     */
    public static void alphabet$set(MemorySegment seg, MemorySegment x) {
        YR_MODIFIER.alphabet$VH.set(seg, x);
    }
    public static MemorySegment alphabet$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)YR_MODIFIER.alphabet$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void alphabet$set(MemorySegment seg, long index, MemorySegment x) {
        YR_MODIFIER.alphabet$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(long len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemorySegment addr, SegmentScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}


