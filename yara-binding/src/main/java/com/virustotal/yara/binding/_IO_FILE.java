// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
/**
 * {@snippet :
 * struct _IO_FILE {
 *     int _flags;
 *     char* _IO_read_ptr;
 *     char* _IO_read_end;
 *     char* _IO_read_base;
 *     char* _IO_write_base;
 *     char* _IO_write_ptr;
 *     char* _IO_write_end;
 *     char* _IO_buf_base;
 *     char* _IO_buf_end;
 *     char* _IO_save_base;
 *     char* _IO_backup_base;
 *     char* _IO_save_end;
 *     struct _IO_marker* _markers;
 *     struct _IO_FILE* _chain;
 *     int _fileno;
 *     int _flags2;
 *     __off_t _old_offset;
 *     unsigned short _cur_column;
 *     signed char _vtable_offset;
 *     char _shortbuf[1];
 *     _IO_lock_t* _lock;
 *     __off64_t _offset;
 *     struct _IO_codecvt* _codecvt;
 *     struct _IO_wide_data* _wide_data;
 *     struct _IO_FILE* _freeres_list;
 *     void* _freeres_buf;
 *     size_t __pad5;
 *     int _mode;
 *     char _unused2[20];
 * };
 * }
 */
public class _IO_FILE {

    static final StructLayout $struct$LAYOUT = MemoryLayout.structLayout(
        Constants$root.C_INT$LAYOUT.withName("_flags"),
        MemoryLayout.paddingLayout(32),
        Constants$root.C_POINTER$LAYOUT.withName("_IO_read_ptr"),
        Constants$root.C_POINTER$LAYOUT.withName("_IO_read_end"),
        Constants$root.C_POINTER$LAYOUT.withName("_IO_read_base"),
        Constants$root.C_POINTER$LAYOUT.withName("_IO_write_base"),
        Constants$root.C_POINTER$LAYOUT.withName("_IO_write_ptr"),
        Constants$root.C_POINTER$LAYOUT.withName("_IO_write_end"),
        Constants$root.C_POINTER$LAYOUT.withName("_IO_buf_base"),
        Constants$root.C_POINTER$LAYOUT.withName("_IO_buf_end"),
        Constants$root.C_POINTER$LAYOUT.withName("_IO_save_base"),
        Constants$root.C_POINTER$LAYOUT.withName("_IO_backup_base"),
        Constants$root.C_POINTER$LAYOUT.withName("_IO_save_end"),
        Constants$root.C_POINTER$LAYOUT.withName("_markers"),
        Constants$root.C_POINTER$LAYOUT.withName("_chain"),
        Constants$root.C_INT$LAYOUT.withName("_fileno"),
        Constants$root.C_INT$LAYOUT.withName("_flags2"),
        Constants$root.C_LONG_LONG$LAYOUT.withName("_old_offset"),
        Constants$root.C_SHORT$LAYOUT.withName("_cur_column"),
        Constants$root.C_CHAR$LAYOUT.withName("_vtable_offset"),
        MemoryLayout.sequenceLayout(1, Constants$root.C_CHAR$LAYOUT).withName("_shortbuf"),
        MemoryLayout.paddingLayout(32),
        Constants$root.C_POINTER$LAYOUT.withName("_lock"),
        Constants$root.C_LONG_LONG$LAYOUT.withName("_offset"),
        Constants$root.C_POINTER$LAYOUT.withName("_codecvt"),
        Constants$root.C_POINTER$LAYOUT.withName("_wide_data"),
        Constants$root.C_POINTER$LAYOUT.withName("_freeres_list"),
        Constants$root.C_POINTER$LAYOUT.withName("_freeres_buf"),
        Constants$root.C_LONG_LONG$LAYOUT.withName("__pad5"),
        Constants$root.C_INT$LAYOUT.withName("_mode"),
        MemoryLayout.sequenceLayout(20, Constants$root.C_CHAR$LAYOUT).withName("_unused2")
    ).withName("_IO_FILE");
    public static MemoryLayout $LAYOUT() {
        return _IO_FILE.$struct$LAYOUT;
    }
    static final VarHandle _flags$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_flags"));
    public static VarHandle _flags$VH() {
        return _IO_FILE._flags$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int _flags;
     * }
     */
    public static int _flags$get(MemorySegment seg) {
        return (int)_IO_FILE._flags$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int _flags;
     * }
     */
    public static void _flags$set(MemorySegment seg, int x) {
        _IO_FILE._flags$VH.set(seg, x);
    }
    public static int _flags$get(MemorySegment seg, long index) {
        return (int)_IO_FILE._flags$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _flags$set(MemorySegment seg, long index, int x) {
        _IO_FILE._flags$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _IO_read_ptr$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_IO_read_ptr"));
    public static VarHandle _IO_read_ptr$VH() {
        return _IO_FILE._IO_read_ptr$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * char* _IO_read_ptr;
     * }
     */
    public static MemorySegment _IO_read_ptr$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_read_ptr$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * char* _IO_read_ptr;
     * }
     */
    public static void _IO_read_ptr$set(MemorySegment seg, MemorySegment x) {
        _IO_FILE._IO_read_ptr$VH.set(seg, x);
    }
    public static MemorySegment _IO_read_ptr$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_read_ptr$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _IO_read_ptr$set(MemorySegment seg, long index, MemorySegment x) {
        _IO_FILE._IO_read_ptr$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _IO_read_end$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_IO_read_end"));
    public static VarHandle _IO_read_end$VH() {
        return _IO_FILE._IO_read_end$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * char* _IO_read_end;
     * }
     */
    public static MemorySegment _IO_read_end$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_read_end$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * char* _IO_read_end;
     * }
     */
    public static void _IO_read_end$set(MemorySegment seg, MemorySegment x) {
        _IO_FILE._IO_read_end$VH.set(seg, x);
    }
    public static MemorySegment _IO_read_end$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_read_end$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _IO_read_end$set(MemorySegment seg, long index, MemorySegment x) {
        _IO_FILE._IO_read_end$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _IO_read_base$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_IO_read_base"));
    public static VarHandle _IO_read_base$VH() {
        return _IO_FILE._IO_read_base$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * char* _IO_read_base;
     * }
     */
    public static MemorySegment _IO_read_base$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_read_base$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * char* _IO_read_base;
     * }
     */
    public static void _IO_read_base$set(MemorySegment seg, MemorySegment x) {
        _IO_FILE._IO_read_base$VH.set(seg, x);
    }
    public static MemorySegment _IO_read_base$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_read_base$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _IO_read_base$set(MemorySegment seg, long index, MemorySegment x) {
        _IO_FILE._IO_read_base$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _IO_write_base$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_IO_write_base"));
    public static VarHandle _IO_write_base$VH() {
        return _IO_FILE._IO_write_base$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * char* _IO_write_base;
     * }
     */
    public static MemorySegment _IO_write_base$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_write_base$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * char* _IO_write_base;
     * }
     */
    public static void _IO_write_base$set(MemorySegment seg, MemorySegment x) {
        _IO_FILE._IO_write_base$VH.set(seg, x);
    }
    public static MemorySegment _IO_write_base$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_write_base$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _IO_write_base$set(MemorySegment seg, long index, MemorySegment x) {
        _IO_FILE._IO_write_base$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _IO_write_ptr$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_IO_write_ptr"));
    public static VarHandle _IO_write_ptr$VH() {
        return _IO_FILE._IO_write_ptr$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * char* _IO_write_ptr;
     * }
     */
    public static MemorySegment _IO_write_ptr$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_write_ptr$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * char* _IO_write_ptr;
     * }
     */
    public static void _IO_write_ptr$set(MemorySegment seg, MemorySegment x) {
        _IO_FILE._IO_write_ptr$VH.set(seg, x);
    }
    public static MemorySegment _IO_write_ptr$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_write_ptr$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _IO_write_ptr$set(MemorySegment seg, long index, MemorySegment x) {
        _IO_FILE._IO_write_ptr$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _IO_write_end$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_IO_write_end"));
    public static VarHandle _IO_write_end$VH() {
        return _IO_FILE._IO_write_end$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * char* _IO_write_end;
     * }
     */
    public static MemorySegment _IO_write_end$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_write_end$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * char* _IO_write_end;
     * }
     */
    public static void _IO_write_end$set(MemorySegment seg, MemorySegment x) {
        _IO_FILE._IO_write_end$VH.set(seg, x);
    }
    public static MemorySegment _IO_write_end$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_write_end$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _IO_write_end$set(MemorySegment seg, long index, MemorySegment x) {
        _IO_FILE._IO_write_end$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _IO_buf_base$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_IO_buf_base"));
    public static VarHandle _IO_buf_base$VH() {
        return _IO_FILE._IO_buf_base$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * char* _IO_buf_base;
     * }
     */
    public static MemorySegment _IO_buf_base$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_buf_base$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * char* _IO_buf_base;
     * }
     */
    public static void _IO_buf_base$set(MemorySegment seg, MemorySegment x) {
        _IO_FILE._IO_buf_base$VH.set(seg, x);
    }
    public static MemorySegment _IO_buf_base$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_buf_base$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _IO_buf_base$set(MemorySegment seg, long index, MemorySegment x) {
        _IO_FILE._IO_buf_base$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _IO_buf_end$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_IO_buf_end"));
    public static VarHandle _IO_buf_end$VH() {
        return _IO_FILE._IO_buf_end$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * char* _IO_buf_end;
     * }
     */
    public static MemorySegment _IO_buf_end$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_buf_end$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * char* _IO_buf_end;
     * }
     */
    public static void _IO_buf_end$set(MemorySegment seg, MemorySegment x) {
        _IO_FILE._IO_buf_end$VH.set(seg, x);
    }
    public static MemorySegment _IO_buf_end$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_buf_end$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _IO_buf_end$set(MemorySegment seg, long index, MemorySegment x) {
        _IO_FILE._IO_buf_end$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _IO_save_base$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_IO_save_base"));
    public static VarHandle _IO_save_base$VH() {
        return _IO_FILE._IO_save_base$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * char* _IO_save_base;
     * }
     */
    public static MemorySegment _IO_save_base$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_save_base$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * char* _IO_save_base;
     * }
     */
    public static void _IO_save_base$set(MemorySegment seg, MemorySegment x) {
        _IO_FILE._IO_save_base$VH.set(seg, x);
    }
    public static MemorySegment _IO_save_base$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_save_base$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _IO_save_base$set(MemorySegment seg, long index, MemorySegment x) {
        _IO_FILE._IO_save_base$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _IO_backup_base$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_IO_backup_base"));
    public static VarHandle _IO_backup_base$VH() {
        return _IO_FILE._IO_backup_base$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * char* _IO_backup_base;
     * }
     */
    public static MemorySegment _IO_backup_base$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_backup_base$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * char* _IO_backup_base;
     * }
     */
    public static void _IO_backup_base$set(MemorySegment seg, MemorySegment x) {
        _IO_FILE._IO_backup_base$VH.set(seg, x);
    }
    public static MemorySegment _IO_backup_base$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_backup_base$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _IO_backup_base$set(MemorySegment seg, long index, MemorySegment x) {
        _IO_FILE._IO_backup_base$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _IO_save_end$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_IO_save_end"));
    public static VarHandle _IO_save_end$VH() {
        return _IO_FILE._IO_save_end$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * char* _IO_save_end;
     * }
     */
    public static MemorySegment _IO_save_end$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_save_end$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * char* _IO_save_end;
     * }
     */
    public static void _IO_save_end$set(MemorySegment seg, MemorySegment x) {
        _IO_FILE._IO_save_end$VH.set(seg, x);
    }
    public static MemorySegment _IO_save_end$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._IO_save_end$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _IO_save_end$set(MemorySegment seg, long index, MemorySegment x) {
        _IO_FILE._IO_save_end$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _markers$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_markers"));
    public static VarHandle _markers$VH() {
        return _IO_FILE._markers$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * struct _IO_marker* _markers;
     * }
     */
    public static MemorySegment _markers$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._markers$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * struct _IO_marker* _markers;
     * }
     */
    public static void _markers$set(MemorySegment seg, MemorySegment x) {
        _IO_FILE._markers$VH.set(seg, x);
    }
    public static MemorySegment _markers$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._markers$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _markers$set(MemorySegment seg, long index, MemorySegment x) {
        _IO_FILE._markers$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _chain$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_chain"));
    public static VarHandle _chain$VH() {
        return _IO_FILE._chain$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * struct _IO_FILE* _chain;
     * }
     */
    public static MemorySegment _chain$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._chain$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * struct _IO_FILE* _chain;
     * }
     */
    public static void _chain$set(MemorySegment seg, MemorySegment x) {
        _IO_FILE._chain$VH.set(seg, x);
    }
    public static MemorySegment _chain$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._chain$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _chain$set(MemorySegment seg, long index, MemorySegment x) {
        _IO_FILE._chain$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _fileno$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_fileno"));
    public static VarHandle _fileno$VH() {
        return _IO_FILE._fileno$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int _fileno;
     * }
     */
    public static int _fileno$get(MemorySegment seg) {
        return (int)_IO_FILE._fileno$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int _fileno;
     * }
     */
    public static void _fileno$set(MemorySegment seg, int x) {
        _IO_FILE._fileno$VH.set(seg, x);
    }
    public static int _fileno$get(MemorySegment seg, long index) {
        return (int)_IO_FILE._fileno$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _fileno$set(MemorySegment seg, long index, int x) {
        _IO_FILE._fileno$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _flags2$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_flags2"));
    public static VarHandle _flags2$VH() {
        return _IO_FILE._flags2$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int _flags2;
     * }
     */
    public static int _flags2$get(MemorySegment seg) {
        return (int)_IO_FILE._flags2$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int _flags2;
     * }
     */
    public static void _flags2$set(MemorySegment seg, int x) {
        _IO_FILE._flags2$VH.set(seg, x);
    }
    public static int _flags2$get(MemorySegment seg, long index) {
        return (int)_IO_FILE._flags2$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _flags2$set(MemorySegment seg, long index, int x) {
        _IO_FILE._flags2$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _old_offset$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_old_offset"));
    public static VarHandle _old_offset$VH() {
        return _IO_FILE._old_offset$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * __off_t _old_offset;
     * }
     */
    public static long _old_offset$get(MemorySegment seg) {
        return (long)_IO_FILE._old_offset$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * __off_t _old_offset;
     * }
     */
    public static void _old_offset$set(MemorySegment seg, long x) {
        _IO_FILE._old_offset$VH.set(seg, x);
    }
    public static long _old_offset$get(MemorySegment seg, long index) {
        return (long)_IO_FILE._old_offset$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _old_offset$set(MemorySegment seg, long index, long x) {
        _IO_FILE._old_offset$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _cur_column$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_cur_column"));
    public static VarHandle _cur_column$VH() {
        return _IO_FILE._cur_column$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * unsigned short _cur_column;
     * }
     */
    public static short _cur_column$get(MemorySegment seg) {
        return (short)_IO_FILE._cur_column$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * unsigned short _cur_column;
     * }
     */
    public static void _cur_column$set(MemorySegment seg, short x) {
        _IO_FILE._cur_column$VH.set(seg, x);
    }
    public static short _cur_column$get(MemorySegment seg, long index) {
        return (short)_IO_FILE._cur_column$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _cur_column$set(MemorySegment seg, long index, short x) {
        _IO_FILE._cur_column$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _vtable_offset$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_vtable_offset"));
    public static VarHandle _vtable_offset$VH() {
        return _IO_FILE._vtable_offset$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * signed char _vtable_offset;
     * }
     */
    public static byte _vtable_offset$get(MemorySegment seg) {
        return (byte)_IO_FILE._vtable_offset$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * signed char _vtable_offset;
     * }
     */
    public static void _vtable_offset$set(MemorySegment seg, byte x) {
        _IO_FILE._vtable_offset$VH.set(seg, x);
    }
    public static byte _vtable_offset$get(MemorySegment seg, long index) {
        return (byte)_IO_FILE._vtable_offset$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _vtable_offset$set(MemorySegment seg, long index, byte x) {
        _IO_FILE._vtable_offset$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static MemorySegment _shortbuf$slice(MemorySegment seg) {
        return seg.asSlice(131, 1);
    }
    static final VarHandle _lock$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_lock"));
    public static VarHandle _lock$VH() {
        return _IO_FILE._lock$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * _IO_lock_t* _lock;
     * }
     */
    public static MemorySegment _lock$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._lock$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * _IO_lock_t* _lock;
     * }
     */
    public static void _lock$set(MemorySegment seg, MemorySegment x) {
        _IO_FILE._lock$VH.set(seg, x);
    }
    public static MemorySegment _lock$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._lock$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _lock$set(MemorySegment seg, long index, MemorySegment x) {
        _IO_FILE._lock$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _offset$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_offset"));
    public static VarHandle _offset$VH() {
        return _IO_FILE._offset$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * __off64_t _offset;
     * }
     */
    public static long _offset$get(MemorySegment seg) {
        return (long)_IO_FILE._offset$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * __off64_t _offset;
     * }
     */
    public static void _offset$set(MemorySegment seg, long x) {
        _IO_FILE._offset$VH.set(seg, x);
    }
    public static long _offset$get(MemorySegment seg, long index) {
        return (long)_IO_FILE._offset$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _offset$set(MemorySegment seg, long index, long x) {
        _IO_FILE._offset$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _codecvt$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_codecvt"));
    public static VarHandle _codecvt$VH() {
        return _IO_FILE._codecvt$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * struct _IO_codecvt* _codecvt;
     * }
     */
    public static MemorySegment _codecvt$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._codecvt$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * struct _IO_codecvt* _codecvt;
     * }
     */
    public static void _codecvt$set(MemorySegment seg, MemorySegment x) {
        _IO_FILE._codecvt$VH.set(seg, x);
    }
    public static MemorySegment _codecvt$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._codecvt$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _codecvt$set(MemorySegment seg, long index, MemorySegment x) {
        _IO_FILE._codecvt$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _wide_data$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_wide_data"));
    public static VarHandle _wide_data$VH() {
        return _IO_FILE._wide_data$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * struct _IO_wide_data* _wide_data;
     * }
     */
    public static MemorySegment _wide_data$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._wide_data$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * struct _IO_wide_data* _wide_data;
     * }
     */
    public static void _wide_data$set(MemorySegment seg, MemorySegment x) {
        _IO_FILE._wide_data$VH.set(seg, x);
    }
    public static MemorySegment _wide_data$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._wide_data$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _wide_data$set(MemorySegment seg, long index, MemorySegment x) {
        _IO_FILE._wide_data$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _freeres_list$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_freeres_list"));
    public static VarHandle _freeres_list$VH() {
        return _IO_FILE._freeres_list$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * struct _IO_FILE* _freeres_list;
     * }
     */
    public static MemorySegment _freeres_list$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._freeres_list$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * struct _IO_FILE* _freeres_list;
     * }
     */
    public static void _freeres_list$set(MemorySegment seg, MemorySegment x) {
        _IO_FILE._freeres_list$VH.set(seg, x);
    }
    public static MemorySegment _freeres_list$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._freeres_list$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _freeres_list$set(MemorySegment seg, long index, MemorySegment x) {
        _IO_FILE._freeres_list$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _freeres_buf$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_freeres_buf"));
    public static VarHandle _freeres_buf$VH() {
        return _IO_FILE._freeres_buf$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * void* _freeres_buf;
     * }
     */
    public static MemorySegment _freeres_buf$get(MemorySegment seg) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._freeres_buf$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * void* _freeres_buf;
     * }
     */
    public static void _freeres_buf$set(MemorySegment seg, MemorySegment x) {
        _IO_FILE._freeres_buf$VH.set(seg, x);
    }
    public static MemorySegment _freeres_buf$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemorySegment)_IO_FILE._freeres_buf$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _freeres_buf$set(MemorySegment seg, long index, MemorySegment x) {
        _IO_FILE._freeres_buf$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle __pad5$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("__pad5"));
    public static VarHandle __pad5$VH() {
        return _IO_FILE.__pad5$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * size_t __pad5;
     * }
     */
    public static long __pad5$get(MemorySegment seg) {
        return (long)_IO_FILE.__pad5$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * size_t __pad5;
     * }
     */
    public static void __pad5$set(MemorySegment seg, long x) {
        _IO_FILE.__pad5$VH.set(seg, x);
    }
    public static long __pad5$get(MemorySegment seg, long index) {
        return (long)_IO_FILE.__pad5$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void __pad5$set(MemorySegment seg, long index, long x) {
        _IO_FILE.__pad5$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle _mode$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("_mode"));
    public static VarHandle _mode$VH() {
        return _IO_FILE._mode$VH;
    }
    /**
     * Getter for field:
     * {@snippet :
     * int _mode;
     * }
     */
    public static int _mode$get(MemorySegment seg) {
        return (int)_IO_FILE._mode$VH.get(seg);
    }
    /**
     * Setter for field:
     * {@snippet :
     * int _mode;
     * }
     */
    public static void _mode$set(MemorySegment seg, int x) {
        _IO_FILE._mode$VH.set(seg, x);
    }
    public static int _mode$get(MemorySegment seg, long index) {
        return (int)_IO_FILE._mode$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void _mode$set(MemorySegment seg, long index, int x) {
        _IO_FILE._mode$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static MemorySegment _unused2$slice(MemorySegment seg) {
        return seg.asSlice(196, 20);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(long len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemorySegment addr, SegmentScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}


