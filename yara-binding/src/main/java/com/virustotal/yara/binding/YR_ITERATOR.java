// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
/**
 * {@snippet :
 * struct YR_ITERATOR {
 *     YR_ITERATOR_NEXT_FUNC next;
 *     union {
 *         struct YR_ARRAY_ITERATOR array_it;
 *         struct YR_DICT_ITERATOR dict_it;
 *         struct YR_INT_RANGE_ITERATOR int_range_it;
 *         struct YR_INT_ENUM_ITERATOR int_enum_it;
 *     };
 * };
 * }
 */
public class YR_ITERATOR {

    static final StructLayout $struct$LAYOUT = MemoryLayout.structLayout(
        Constants$root.C_POINTER$LAYOUT.withName("next"),
        MemoryLayout.unionLayout(
            MemoryLayout.structLayout(
                Constants$root.C_POINTER$LAYOUT.withName("array"),
                Constants$root.C_INT$LAYOUT.withName("index"),
                MemoryLayout.paddingLayout(32)
            ).withName("array_it"),
            MemoryLayout.structLayout(
                Constants$root.C_POINTER$LAYOUT.withName("dict"),
                Constants$root.C_INT$LAYOUT.withName("index"),
                MemoryLayout.paddingLayout(32)
            ).withName("dict_it"),
            MemoryLayout.structLayout(
                Constants$root.C_LONG_LONG$LAYOUT.withName("next"),
                Constants$root.C_LONG_LONG$LAYOUT.withName("last")
            ).withName("int_range_it"),
            MemoryLayout.structLayout(
                Constants$root.C_LONG_LONG$LAYOUT.withName("next"),
                Constants$root.C_LONG_LONG$LAYOUT.withName("count"),
                MemoryLayout.sequenceLayout(1, Constants$root.C_LONG_LONG$LAYOUT).withName("items")
            ).withName("int_enum_it")
        ).withName("$anon$0")
    ).withName("YR_ITERATOR");
    public static MemoryLayout $LAYOUT() {
        return YR_ITERATOR.$struct$LAYOUT;
    }
    static final VarHandle next$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("next"));
    public static VarHandle next$VH() {
        return YR_ITERATOR.next$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * YR_ITERATOR_NEXT_FUNC next;
     * }
     */
    public static MemorySegment next$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)YR_ITERATOR.next$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * YR_ITERATOR_NEXT_FUNC next;
     * }
     */
    public static void next$set(MemorySegment seg, MemorySegment x) {
        YR_ITERATOR.next$VH.set(seg, x);
    }
    public static MemorySegment next$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)YR_ITERATOR.next$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void next$set(MemorySegment seg, long index, MemorySegment x) {
        YR_ITERATOR.next$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static YR_ITERATOR_NEXT_FUNC next(MemorySegment segment, SegmentScope scope) {
        return YR_ITERATOR_NEXT_FUNC.ofAddress(next$get(segment), scope);
    }
    public static MemorySegment array_it$slice(MemorySegment seg) {
        return seg.asSlice(8, 16);
    }
    public static MemorySegment dict_it$slice(MemorySegment seg) {
        return seg.asSlice(8, 16);
    }
    public static MemorySegment int_range_it$slice(MemorySegment seg) {
        return seg.asSlice(8, 16);
    }
    public static MemorySegment int_enum_it$slice(MemorySegment seg) {
        return seg.asSlice(8, 24);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(long len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemorySegment addr, SegmentScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}


