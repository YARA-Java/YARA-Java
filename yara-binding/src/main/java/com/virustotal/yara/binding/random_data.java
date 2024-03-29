// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
/**
 * {@snippet :
 * struct random_data {
 *     int32_t* fptr;
 *     int32_t* rptr;
 *     int32_t* state;
 *     int rand_type;
 *     int rand_deg;
 *     int rand_sep;
 *     int32_t* end_ptr;
 * };
 * }
 */
public class random_data {

    static final StructLayout $struct$LAYOUT = MemoryLayout.structLayout(
        Constants$root.C_POINTER$LAYOUT.withName("fptr"),
        Constants$root.C_POINTER$LAYOUT.withName("rptr"),
        Constants$root.C_POINTER$LAYOUT.withName("state"),
        Constants$root.C_INT$LAYOUT.withName("rand_type"),
        Constants$root.C_INT$LAYOUT.withName("rand_deg"),
        Constants$root.C_INT$LAYOUT.withName("rand_sep"),
        MemoryLayout.paddingLayout(32),
        Constants$root.C_POINTER$LAYOUT.withName("end_ptr")
    ).withName("random_data");
    public static MemoryLayout $LAYOUT() {
        return random_data.$struct$LAYOUT;
    }
    static final VarHandle fptr$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("fptr"));
    public static VarHandle fptr$VH() {
        return random_data.fptr$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int32_t* fptr;
     * }
     */
    public static MemorySegment fptr$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)random_data.fptr$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int32_t* fptr;
     * }
     */
    public static void fptr$set(MemorySegment seg, MemorySegment x) {
        random_data.fptr$VH.set(seg, x);
    }
    public static MemorySegment fptr$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)random_data.fptr$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void fptr$set(MemorySegment seg, long index, MemorySegment x) {
        random_data.fptr$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle rptr$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("rptr"));
    public static VarHandle rptr$VH() {
        return random_data.rptr$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int32_t* rptr;
     * }
     */
    public static MemorySegment rptr$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)random_data.rptr$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int32_t* rptr;
     * }
     */
    public static void rptr$set(MemorySegment seg, MemorySegment x) {
        random_data.rptr$VH.set(seg, x);
    }
    public static MemorySegment rptr$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)random_data.rptr$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void rptr$set(MemorySegment seg, long index, MemorySegment x) {
        random_data.rptr$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle state$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("state"));
    public static VarHandle state$VH() {
        return random_data.state$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int32_t* state;
     * }
     */
    public static MemorySegment state$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)random_data.state$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int32_t* state;
     * }
     */
    public static void state$set(MemorySegment seg, MemorySegment x) {
        random_data.state$VH.set(seg, x);
    }
    public static MemorySegment state$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)random_data.state$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void state$set(MemorySegment seg, long index, MemorySegment x) {
        random_data.state$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle rand_type$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("rand_type"));
    public static VarHandle rand_type$VH() {
        return random_data.rand_type$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int rand_type;
     * }
     */
    public static int rand_type$get(MemorySegment seg) {
        return (int)random_data.rand_type$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int rand_type;
     * }
     */
    public static void rand_type$set(MemorySegment seg, int x) {
        random_data.rand_type$VH.set(seg, x);
    }
    public static int rand_type$get(MemorySegment seg, long index) {
        return (int)random_data.rand_type$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void rand_type$set(MemorySegment seg, long index, int x) {
        random_data.rand_type$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle rand_deg$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("rand_deg"));
    public static VarHandle rand_deg$VH() {
        return random_data.rand_deg$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int rand_deg;
     * }
     */
    public static int rand_deg$get(MemorySegment seg) {
        return (int)random_data.rand_deg$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int rand_deg;
     * }
     */
    public static void rand_deg$set(MemorySegment seg, int x) {
        random_data.rand_deg$VH.set(seg, x);
    }
    public static int rand_deg$get(MemorySegment seg, long index) {
        return (int)random_data.rand_deg$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void rand_deg$set(MemorySegment seg, long index, int x) {
        random_data.rand_deg$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle rand_sep$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("rand_sep"));
    public static VarHandle rand_sep$VH() {
        return random_data.rand_sep$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int rand_sep;
     * }
     */
    public static int rand_sep$get(MemorySegment seg) {
        return (int)random_data.rand_sep$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int rand_sep;
     * }
     */
    public static void rand_sep$set(MemorySegment seg, int x) {
        random_data.rand_sep$VH.set(seg, x);
    }
    public static int rand_sep$get(MemorySegment seg, long index) {
        return (int)random_data.rand_sep$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void rand_sep$set(MemorySegment seg, long index, int x) {
        random_data.rand_sep$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle end_ptr$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("end_ptr"));
    public static VarHandle end_ptr$VH() {
        return random_data.end_ptr$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int32_t* end_ptr;
     * }
     */
    public static MemorySegment end_ptr$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)random_data.end_ptr$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int32_t* end_ptr;
     * }
     */
    public static void end_ptr$set(MemorySegment seg, MemorySegment x) {
        random_data.end_ptr$VH.set(seg, x);
    }
    public static MemorySegment end_ptr$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)random_data.end_ptr$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void end_ptr$set(MemorySegment seg, long index, MemorySegment x) {
        random_data.end_ptr$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(long len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemorySegment addr, SegmentScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}


