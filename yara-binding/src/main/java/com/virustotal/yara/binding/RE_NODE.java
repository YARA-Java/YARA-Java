// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
/**
 * {@snippet :
 * struct RE_NODE {
 *     int type;
 *     union {
 *         int value;
 *         int count;
 *         int start;
 *     };
 *     union {
 *         int mask;
 *         int end;
 *     };
 *     int greedy;
 *     RE_CLASS* re_class;
 *     RE_NODE* children_head;
 *     RE_NODE* children_tail;
 *     RE_NODE* prev_sibling;
 *     RE_NODE* next_sibling;
 *     YR_ARENA_REF forward_code_ref;
 *     YR_ARENA_REF backward_code_ref;
 * };
 * }
 */
public class RE_NODE {

    static final StructLayout $struct$LAYOUT = MemoryLayout.structLayout(
        Constants$root.C_INT$LAYOUT.withName("type"),
        MemoryLayout.unionLayout(
            Constants$root.C_INT$LAYOUT.withName("value"),
            Constants$root.C_INT$LAYOUT.withName("count"),
            Constants$root.C_INT$LAYOUT.withName("start")
        ).withName("$anon$0"),
        MemoryLayout.unionLayout(
            Constants$root.C_INT$LAYOUT.withName("mask"),
            Constants$root.C_INT$LAYOUT.withName("end")
        ).withName("$anon$1"),
        Constants$root.C_INT$LAYOUT.withName("greedy"),
        Constants$root.C_POINTER$LAYOUT.withName("re_class"),
        Constants$root.C_POINTER$LAYOUT.withName("children_head"),
        Constants$root.C_POINTER$LAYOUT.withName("children_tail"),
        Constants$root.C_POINTER$LAYOUT.withName("prev_sibling"),
        Constants$root.C_POINTER$LAYOUT.withName("next_sibling"),
        MemoryLayout.structLayout(
            Constants$root.C_INT$LAYOUT.withName("buffer_id"),
            Constants$root.C_INT$LAYOUT.withName("offset")
        ).withName("forward_code_ref"),
        MemoryLayout.structLayout(
            Constants$root.C_INT$LAYOUT.withName("buffer_id"),
            Constants$root.C_INT$LAYOUT.withName("offset")
        ).withName("backward_code_ref")
    ).withName("RE_NODE");
    public static MemoryLayout $LAYOUT() {
        return RE_NODE.$struct$LAYOUT;
    }
    static final VarHandle type$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("type"));
    public static VarHandle type$VH() {
        return RE_NODE.type$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int type;
     * }
     */
    public static int type$get(MemorySegment seg) {
        return (int)RE_NODE.type$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int type;
     * }
     */
    public static void type$set(MemorySegment seg, int x) {
        RE_NODE.type$VH.set(seg, x);
    }
    public static int type$get(MemorySegment seg, long index) {
        return (int)RE_NODE.type$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void type$set(MemorySegment seg, long index, int x) {
        RE_NODE.type$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle value$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("$anon$0"), MemoryLayout.PathElement.groupElement("value"));
    public static VarHandle value$VH() {
        return RE_NODE.value$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int value;
     * }
     */
    public static int value$get(MemorySegment seg) {
        return (int)RE_NODE.value$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int value;
     * }
     */
    public static void value$set(MemorySegment seg, int x) {
        RE_NODE.value$VH.set(seg, x);
    }
    public static int value$get(MemorySegment seg, long index) {
        return (int)RE_NODE.value$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void value$set(MemorySegment seg, long index, int x) {
        RE_NODE.value$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle count$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("$anon$0"), MemoryLayout.PathElement.groupElement("count"));
    public static VarHandle count$VH() {
        return RE_NODE.count$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int count;
     * }
     */
    public static int count$get(MemorySegment seg) {
        return (int)RE_NODE.count$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int count;
     * }
     */
    public static void count$set(MemorySegment seg, int x) {
        RE_NODE.count$VH.set(seg, x);
    }
    public static int count$get(MemorySegment seg, long index) {
        return (int)RE_NODE.count$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void count$set(MemorySegment seg, long index, int x) {
        RE_NODE.count$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle start$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("$anon$0"), MemoryLayout.PathElement.groupElement("start"));
    public static VarHandle start$VH() {
        return RE_NODE.start$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int start;
     * }
     */
    public static int start$get(MemorySegment seg) {
        return (int)RE_NODE.start$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int start;
     * }
     */
    public static void start$set(MemorySegment seg, int x) {
        RE_NODE.start$VH.set(seg, x);
    }
    public static int start$get(MemorySegment seg, long index) {
        return (int)RE_NODE.start$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void start$set(MemorySegment seg, long index, int x) {
        RE_NODE.start$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle mask$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("$anon$1"), MemoryLayout.PathElement.groupElement("mask"));
    public static VarHandle mask$VH() {
        return RE_NODE.mask$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int mask;
     * }
     */
    public static int mask$get(MemorySegment seg) {
        return (int)RE_NODE.mask$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int mask;
     * }
     */
    public static void mask$set(MemorySegment seg, int x) {
        RE_NODE.mask$VH.set(seg, x);
    }
    public static int mask$get(MemorySegment seg, long index) {
        return (int)RE_NODE.mask$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void mask$set(MemorySegment seg, long index, int x) {
        RE_NODE.mask$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle end$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("$anon$1"), MemoryLayout.PathElement.groupElement("end"));
    public static VarHandle end$VH() {
        return RE_NODE.end$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int end;
     * }
     */
    public static int end$get(MemorySegment seg) {
        return (int)RE_NODE.end$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int end;
     * }
     */
    public static void end$set(MemorySegment seg, int x) {
        RE_NODE.end$VH.set(seg, x);
    }
    public static int end$get(MemorySegment seg, long index) {
        return (int)RE_NODE.end$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void end$set(MemorySegment seg, long index, int x) {
        RE_NODE.end$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle greedy$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("greedy"));
    public static VarHandle greedy$VH() {
        return RE_NODE.greedy$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int greedy;
     * }
     */
    public static int greedy$get(MemorySegment seg) {
        return (int)RE_NODE.greedy$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int greedy;
     * }
     */
    public static void greedy$set(MemorySegment seg, int x) {
        RE_NODE.greedy$VH.set(seg, x);
    }
    public static int greedy$get(MemorySegment seg, long index) {
        return (int)RE_NODE.greedy$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void greedy$set(MemorySegment seg, long index, int x) {
        RE_NODE.greedy$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle re_class$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("re_class"));
    public static VarHandle re_class$VH() {
        return RE_NODE.re_class$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * RE_CLASS* re_class;
     * }
     */
    public static MemorySegment re_class$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)RE_NODE.re_class$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * RE_CLASS* re_class;
     * }
     */
    public static void re_class$set(MemorySegment seg, MemorySegment x) {
        RE_NODE.re_class$VH.set(seg, x);
    }
    public static MemorySegment re_class$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)RE_NODE.re_class$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void re_class$set(MemorySegment seg, long index, MemorySegment x) {
        RE_NODE.re_class$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle children_head$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("children_head"));
    public static VarHandle children_head$VH() {
        return RE_NODE.children_head$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * RE_NODE* children_head;
     * }
     */
    public static MemorySegment children_head$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)RE_NODE.children_head$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * RE_NODE* children_head;
     * }
     */
    public static void children_head$set(MemorySegment seg, MemorySegment x) {
        RE_NODE.children_head$VH.set(seg, x);
    }
    public static MemorySegment children_head$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)RE_NODE.children_head$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void children_head$set(MemorySegment seg, long index, MemorySegment x) {
        RE_NODE.children_head$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle children_tail$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("children_tail"));
    public static VarHandle children_tail$VH() {
        return RE_NODE.children_tail$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * RE_NODE* children_tail;
     * }
     */
    public static MemorySegment children_tail$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)RE_NODE.children_tail$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * RE_NODE* children_tail;
     * }
     */
    public static void children_tail$set(MemorySegment seg, MemorySegment x) {
        RE_NODE.children_tail$VH.set(seg, x);
    }
    public static MemorySegment children_tail$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)RE_NODE.children_tail$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void children_tail$set(MemorySegment seg, long index, MemorySegment x) {
        RE_NODE.children_tail$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle prev_sibling$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("prev_sibling"));
    public static VarHandle prev_sibling$VH() {
        return RE_NODE.prev_sibling$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * RE_NODE* prev_sibling;
     * }
     */
    public static MemorySegment prev_sibling$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)RE_NODE.prev_sibling$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * RE_NODE* prev_sibling;
     * }
     */
    public static void prev_sibling$set(MemorySegment seg, MemorySegment x) {
        RE_NODE.prev_sibling$VH.set(seg, x);
    }
    public static MemorySegment prev_sibling$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)RE_NODE.prev_sibling$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void prev_sibling$set(MemorySegment seg, long index, MemorySegment x) {
        RE_NODE.prev_sibling$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle next_sibling$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("next_sibling"));
    public static VarHandle next_sibling$VH() {
        return RE_NODE.next_sibling$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * RE_NODE* next_sibling;
     * }
     */
    public static MemorySegment next_sibling$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)RE_NODE.next_sibling$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * RE_NODE* next_sibling;
     * }
     */
    public static void next_sibling$set(MemorySegment seg, MemorySegment x) {
        RE_NODE.next_sibling$VH.set(seg, x);
    }
    public static MemorySegment next_sibling$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)RE_NODE.next_sibling$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void next_sibling$set(MemorySegment seg, long index, MemorySegment x) {
        RE_NODE.next_sibling$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static MemorySegment forward_code_ref$slice(MemorySegment seg) {
        return seg.asSlice(56, 8);
    }
    public static MemorySegment backward_code_ref$slice(MemorySegment seg) {
        return seg.asSlice(64, 8);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(long len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemorySegment addr, SegmentScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}


