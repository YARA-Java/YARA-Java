// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
final class constants$67 {

    // Suppresses default constructor, ensuring non-instantiability.
    private constants$67() {}
    static final FunctionDescriptor sched_setscheduler$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle sched_setscheduler$MH = RuntimeHelper.downcallHandle(
        "sched_setscheduler",
        constants$67.sched_setscheduler$FUNC
    );
    static final FunctionDescriptor sched_getscheduler$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_INT$LAYOUT
    );
    static final MethodHandle sched_getscheduler$MH = RuntimeHelper.downcallHandle(
        "sched_getscheduler",
        constants$67.sched_getscheduler$FUNC
    );
    static final FunctionDescriptor sched_yield$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT);
    static final MethodHandle sched_yield$MH = RuntimeHelper.downcallHandle(
        "sched_yield",
        constants$67.sched_yield$FUNC
    );
    static final FunctionDescriptor sched_get_priority_max$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_INT$LAYOUT
    );
    static final MethodHandle sched_get_priority_max$MH = RuntimeHelper.downcallHandle(
        "sched_get_priority_max",
        constants$67.sched_get_priority_max$FUNC
    );
    static final FunctionDescriptor sched_get_priority_min$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_INT$LAYOUT
    );
    static final MethodHandle sched_get_priority_min$MH = RuntimeHelper.downcallHandle(
        "sched_get_priority_min",
        constants$67.sched_get_priority_min$FUNC
    );
    static final FunctionDescriptor sched_rr_get_interval$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle sched_rr_get_interval$MH = RuntimeHelper.downcallHandle(
        "sched_rr_get_interval",
        constants$67.sched_rr_get_interval$FUNC
    );
}


