// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
/**
 * {@snippet :
 * struct YR_DICT_ITERATOR {
 *     YR_OBJECT* dict;
 *     int index;
 * };
 * }
 */
public class YR_DICT_ITERATOR {

    static final StructLayout $struct$LAYOUT = MemoryLayout.structLayout(
        Constants$root.C_POINTER$LAYOUT.withName("dict"),
        Constants$root.C_INT$LAYOUT.withName("index"),
        MemoryLayout.paddingLayout(32)
    ).withName("YR_DICT_ITERATOR");
    public static MemoryLayout $LAYOUT() {
        return YR_DICT_ITERATOR.$struct$LAYOUT;
    }
    static final VarHandle dict$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("dict"));
    public static VarHandle dict$VH() {
        return YR_DICT_ITERATOR.dict$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * YR_OBJECT* dict;
     * }
     */
    public static MemorySegment dict$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)YR_DICT_ITERATOR.dict$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * YR_OBJECT* dict;
     * }
     */
    public static void dict$set(MemorySegment seg, MemorySegment x) {
        YR_DICT_ITERATOR.dict$VH.set(seg, x);
    }
    public static MemorySegment dict$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)YR_DICT_ITERATOR.dict$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void dict$set(MemorySegment seg, long index, MemorySegment x) {
        YR_DICT_ITERATOR.dict$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle index$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("index"));
    public static VarHandle index$VH() {
        return YR_DICT_ITERATOR.index$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int index;
     * }
     */
    public static int index$get(MemorySegment seg) {
        return (int)YR_DICT_ITERATOR.index$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int index;
     * }
     */
    public static void index$set(MemorySegment seg, int x) {
        YR_DICT_ITERATOR.index$VH.set(seg, x);
    }
    public static int index$get(MemorySegment seg, long index) {
        return (int)YR_DICT_ITERATOR.index$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void index$set(MemorySegment seg, long index, int x) {
        YR_DICT_ITERATOR.index$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(long len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemorySegment addr, SegmentScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}

