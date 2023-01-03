// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
/**
 * {@snippet :
 * unsigned long (*YR_STREAM_READ_FUNC)(void* ptr,unsigned long size,unsigned long count,void* user_data);
 * }
 */
public interface YR_STREAM_READ_FUNC {

    long apply(java.lang.foreign.MemorySegment ptr, long size, long count, java.lang.foreign.MemorySegment user_data);
    static MemorySegment allocate(YR_STREAM_READ_FUNC fi, SegmentScope scope) {
        return RuntimeHelper.upcallStub(YR_STREAM_READ_FUNC.class, fi, constants$50.YR_STREAM_READ_FUNC$FUNC, scope);
    }
    static YR_STREAM_READ_FUNC ofAddress(MemorySegment addr, SegmentScope scope) {
        MemorySegment symbol = MemorySegment.ofAddress(addr.address(), 0, scope);
        return (java.lang.foreign.MemorySegment _ptr, long _size, long _count, java.lang.foreign.MemorySegment _user_data) -> {
            try {
                return (long)constants$50.YR_STREAM_READ_FUNC$MH.invokeExact(symbol, _ptr, _size, _count, _user_data);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}

