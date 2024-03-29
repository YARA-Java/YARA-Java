// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
/**
 * {@snippet :
 * int (*YR_MODULE_FUNC)(union YR_VALUE* args,struct YR_SCAN_CONTEXT* context,struct YR_OBJECT_FUNCTION* function_obj);
 * }
 */
public interface YR_MODULE_FUNC {

    int apply(java.lang.foreign.MemorySegment args, java.lang.foreign.MemorySegment context, java.lang.foreign.MemorySegment function_obj);
    static MemorySegment allocate(YR_MODULE_FUNC fi, SegmentScope scope) {
        return RuntimeHelper.upcallStub(YR_MODULE_FUNC.class, fi, constants$90.YR_MODULE_FUNC$FUNC, scope);
    }
    static YR_MODULE_FUNC ofAddress(MemorySegment addr, SegmentScope scope) {
        MemorySegment symbol = MemorySegment.ofAddress(addr.address(), 0, scope);
        return (java.lang.foreign.MemorySegment _args, java.lang.foreign.MemorySegment _context, java.lang.foreign.MemorySegment _function_obj) -> {
            try {
                return (int)constants$90.YR_MODULE_FUNC$MH.invokeExact(symbol, _args, _context, _function_obj);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


