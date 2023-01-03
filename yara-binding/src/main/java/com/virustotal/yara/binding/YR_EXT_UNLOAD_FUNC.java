// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
/**
 * {@snippet :
 * int (*YR_EXT_UNLOAD_FUNC)(struct YR_OBJECT* module_object);
 * }
 */
public interface YR_EXT_UNLOAD_FUNC {

    int apply(java.lang.foreign.MemorySegment module_object);
    static MemorySegment allocate(YR_EXT_UNLOAD_FUNC fi, SegmentScope scope) {
        return RuntimeHelper.upcallStub(YR_EXT_UNLOAD_FUNC.class, fi, constants$165.YR_EXT_UNLOAD_FUNC$FUNC, scope);
    }
    static YR_EXT_UNLOAD_FUNC ofAddress(MemorySegment addr, SegmentScope scope) {
        MemorySegment symbol = MemorySegment.ofAddress(addr.address(), 0, scope);
        return (java.lang.foreign.MemorySegment _module_object) -> {
            try {
                return (int)constants$165.YR_EXT_UNLOAD_FUNC$MH.invokeExact(symbol, _module_object);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}

