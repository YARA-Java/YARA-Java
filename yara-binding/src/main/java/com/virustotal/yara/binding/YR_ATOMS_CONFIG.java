// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
/**
 * {@snippet :
 * struct YR_ATOMS_CONFIG {
 *     YR_ATOMS_QUALITY_FUNC get_atom_quality;
 *     YR_ATOM_QUALITY_TABLE_ENTRY* quality_table;
 *     int quality_warning_threshold;
 *     int quality_table_entries;
 *     _Bool free_quality_table;
 * };
 * }
 */
public class YR_ATOMS_CONFIG {

    static final StructLayout $struct$LAYOUT = MemoryLayout.structLayout(
        Constants$root.C_POINTER$LAYOUT.withName("get_atom_quality"),
        Constants$root.C_POINTER$LAYOUT.withName("quality_table"),
        Constants$root.C_INT$LAYOUT.withName("quality_warning_threshold"),
        Constants$root.C_INT$LAYOUT.withName("quality_table_entries"),
        Constants$root.C_BOOL$LAYOUT.withName("free_quality_table"),
        MemoryLayout.paddingLayout(56)
    ).withName("YR_ATOMS_CONFIG");
    public static MemoryLayout $LAYOUT() {
        return YR_ATOMS_CONFIG.$struct$LAYOUT;
    }
    static final VarHandle get_atom_quality$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("get_atom_quality"));
    public static VarHandle get_atom_quality$VH() {
        return YR_ATOMS_CONFIG.get_atom_quality$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * YR_ATOMS_QUALITY_FUNC get_atom_quality;
     * }
     */
    public static MemorySegment get_atom_quality$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)YR_ATOMS_CONFIG.get_atom_quality$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * YR_ATOMS_QUALITY_FUNC get_atom_quality;
     * }
     */
    public static void get_atom_quality$set(MemorySegment seg, MemorySegment x) {
        YR_ATOMS_CONFIG.get_atom_quality$VH.set(seg, x);
    }
    public static MemorySegment get_atom_quality$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)YR_ATOMS_CONFIG.get_atom_quality$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void get_atom_quality$set(MemorySegment seg, long index, MemorySegment x) {
        YR_ATOMS_CONFIG.get_atom_quality$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static YR_ATOMS_QUALITY_FUNC get_atom_quality(MemorySegment segment, SegmentScope scope) {
        return YR_ATOMS_QUALITY_FUNC.ofAddress(get_atom_quality$get(segment), scope);
    }
    static final VarHandle quality_table$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("quality_table"));
    public static VarHandle quality_table$VH() {
        return YR_ATOMS_CONFIG.quality_table$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * YR_ATOM_QUALITY_TABLE_ENTRY* quality_table;
     * }
     */
    public static MemorySegment quality_table$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)YR_ATOMS_CONFIG.quality_table$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * YR_ATOM_QUALITY_TABLE_ENTRY* quality_table;
     * }
     */
    public static void quality_table$set(MemorySegment seg, MemorySegment x) {
        YR_ATOMS_CONFIG.quality_table$VH.set(seg, x);
    }
    public static MemorySegment quality_table$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)YR_ATOMS_CONFIG.quality_table$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void quality_table$set(MemorySegment seg, long index, MemorySegment x) {
        YR_ATOMS_CONFIG.quality_table$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle quality_warning_threshold$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("quality_warning_threshold"));
    public static VarHandle quality_warning_threshold$VH() {
        return YR_ATOMS_CONFIG.quality_warning_threshold$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int quality_warning_threshold;
     * }
     */
    public static int quality_warning_threshold$get(MemorySegment seg) {
        return (int)YR_ATOMS_CONFIG.quality_warning_threshold$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int quality_warning_threshold;
     * }
     */
    public static void quality_warning_threshold$set(MemorySegment seg, int x) {
        YR_ATOMS_CONFIG.quality_warning_threshold$VH.set(seg, x);
    }
    public static int quality_warning_threshold$get(MemorySegment seg, long index) {
        return (int)YR_ATOMS_CONFIG.quality_warning_threshold$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void quality_warning_threshold$set(MemorySegment seg, long index, int x) {
        YR_ATOMS_CONFIG.quality_warning_threshold$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle quality_table_entries$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("quality_table_entries"));
    public static VarHandle quality_table_entries$VH() {
        return YR_ATOMS_CONFIG.quality_table_entries$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int quality_table_entries;
     * }
     */
    public static int quality_table_entries$get(MemorySegment seg) {
        return (int)YR_ATOMS_CONFIG.quality_table_entries$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int quality_table_entries;
     * }
     */
    public static void quality_table_entries$set(MemorySegment seg, int x) {
        YR_ATOMS_CONFIG.quality_table_entries$VH.set(seg, x);
    }
    public static int quality_table_entries$get(MemorySegment seg, long index) {
        return (int)YR_ATOMS_CONFIG.quality_table_entries$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void quality_table_entries$set(MemorySegment seg, long index, int x) {
        YR_ATOMS_CONFIG.quality_table_entries$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle free_quality_table$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("free_quality_table"));
    public static VarHandle free_quality_table$VH() {
        return YR_ATOMS_CONFIG.free_quality_table$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * _Bool free_quality_table;
     * }
     */
    public static boolean free_quality_table$get(MemorySegment seg) {
        return (boolean)YR_ATOMS_CONFIG.free_quality_table$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * _Bool free_quality_table;
     * }
     */
    public static void free_quality_table$set(MemorySegment seg, boolean x) {
        YR_ATOMS_CONFIG.free_quality_table$VH.set(seg, x);
    }
    public static boolean free_quality_table$get(MemorySegment seg, long index) {
        return (boolean)YR_ATOMS_CONFIG.free_quality_table$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void free_quality_table$set(MemorySegment seg, long index, boolean x) {
        YR_ATOMS_CONFIG.free_quality_table$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(long len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemorySegment addr, SegmentScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}


