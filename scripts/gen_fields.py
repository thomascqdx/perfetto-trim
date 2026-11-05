"""Generate src/pftrim/fields.py from perfetto_trace_pb2's descriptor.

Usage (from repo root, dev venv active):

    .venv\\Scripts\\python scripts\\gen_fields.py

Output contains only plain int constants -- no protobuf import at runtime.
"""

from __future__ import annotations

import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = REPO_ROOT / "src" / "pftrim" / "fields.py"

# Messages to emit as constant classes. Value = list of nested message types
# to also emit (empty tuple = none, None = all nested types).
MESSAGES: dict[str, tuple[str, ...] | None] = {
    "Trace": (),
    "TracePacket": (),
    "TracePacketDefaults": (),
    "FtraceEventBundle": ("CompactSched", "FtraceError", "GenericEventDescriptor"),
    "FtraceEvent": (),
    "PrintFtraceEvent": (),
    "SchedSwitchFtraceEvent": (),
    "SchedWakingFtraceEvent": (),
    "CpuFrequencyFtraceEvent": (),
    "CpuIdleFtraceEvent": (),
    "TaskNewtaskFtraceEvent": (),
    "TaskRenameFtraceEvent": (),
    "BinderTransactionFtraceEvent": (),
    "BinderTransactionReceivedFtraceEvent": (),
    "BinderTransactionAllocBufFtraceEvent": (),
    "AndroidLogPacket": ("LogEvent", "Stats"),
    "ProcessTree": None,
    "ProcessStats": None,
    "SysStats": None,
    "ClockSnapshot": ("Clock",),
    "TracingServiceEvent": (),
    "ProfilePacket": None,
    "StreamingProfilePacket": (),
    "PerfSample": (),
    "GraphicsFrameEvent": ("BufferEvent",),
    "InternedData": (),
    "TrackEvent": (),
    "TrackDescriptor": None,
    "BatteryCounters": (),
    "PowerRails": None,
}

# Messages missing from perfetto 0.58.2's bundled perfetto_trace_pb2 but
# needed by later milestones. Transcribed by hand from upstream
# protos/perfetto/trace/android/frame_timeline_event.proto @ v57.0.
EXTRA_MESSAGES: dict[str, dict[str, object]] = {
    "FrameTimelineEvent": {
        "EXPECTED_DISPLAY_FRAME_START": 1,
        "ACTUAL_DISPLAY_FRAME_START": 2,
        "EXPECTED_SURFACE_FRAME_START": 3,
        "ACTUAL_SURFACE_FRAME_START": 4,
        "FRAME_END": 5,
        "__nested__": {
            "ExpectedSurfaceFrameStart": {
                "COOKIE": 1, "TOKEN": 2, "DISPLAY_FRAME_TOKEN": 3,
                "PID": 4, "LAYER_NAME": 5,
            },
            "ActualSurfaceFrameStart": {
                "COOKIE": 1, "TOKEN": 2, "DISPLAY_FRAME_TOKEN": 3,
                "PID": 4, "LAYER_NAME": 5, "PRESENT_TYPE": 6,
                "ON_TIME_FINISH": 7, "GPU_COMPOSITION": 8, "JANK_TYPE": 9,
                "PREDICTION_TYPE": 10, "IS_BUFFER": 11,
                "JANK_SEVERITY_TYPE": 12, "PRESENT_DELAY_MILLIS": 13,
                "VSYNC_RESYNCED_JITTER_MILLIS": 14,
                "JANK_SEVERITY_SCORE": 15, "JANK_TYPE_EXPERIMENTAL": 16,
                "PRESENT_TYPE_EXPERIMENTAL": 17, "JANK_DEBUG_METADATA": 18,
                "LATCHED_FENCE_STATE": 19, "ANIMATION_TIME_MILLIS": 20,
            },
            "ExpectedDisplayFrameStart": {"COOKIE": 1, "TOKEN": 2, "PID": 3},
            "ActualDisplayFrameStart": {
                "COOKIE": 1, "TOKEN": 2, "PID": 3, "PRESENT_TYPE": 4,
                "ON_TIME_FINISH": 5, "GPU_COMPOSITION": 6, "JANK_TYPE": 7,
                "PREDICTION_TYPE": 8, "JANK_SEVERITY_TYPE": 9,
                "PRESENT_DELAY_MILLIS": 10, "JANK_SEVERITY_SCORE": 11,
                "JANK_TYPE_EXPERIMENTAL": 12,
                "PRESENT_TYPE_EXPERIMENTAL": 13, "JANK_DEBUG_METADATA": 14,
                "LATCHED_UNSIGNALED_COUNT": 15,
                "ADDRESSABLE_UNSIGNALED_LATCH_COUNT": 16,
            },
            "FrameEnd": {"COOKIE": 1},
        },
    },
}

# TracePacket fields missing from this pb2 version (frame_timeline_event = 76
# exists upstream @ v57.0 but not in perfetto 0.58.2's bundled proto).
EXTRA_TRACE_PACKET_FIELDS = {"FRAME_TIMELINE_EVENT": 76}

# Module-level enum constants to emit: (constant_prefix, enum full name suffix)
ENUMS = [
    ("", "TracePacket.SequenceFlags"),
    ("", "BuiltinClock"),
    ("", "FtraceClock"),
    ("", "AndroidLogPriority"),
]


def const_name(field_name: str) -> str:
    return re.sub(r"[^A-Z0-9]", "_", field_name.upper())


def emit_fields(desc, nested_spec, lines: list[str], indent: str) -> None:
    seen: set[str] = set()
    for f in sorted(desc.fields, key=lambda f: f.number):
        name = const_name(f.name)
        if name in seen:
            name = f"{name}_{f.number}"
        seen.add(name)
        lines.append(f"{indent}{name} = {f.number}")
    nested = desc.nested_types
    if nested_spec is not None:
        nested = [n for n in nested if n.name in nested_spec]
    for n in nested:
        lines.append("")
        lines.append(f"{indent}class {n.name}:")
        emit_fields(n, None, lines, indent + "    ")


def emit_extra(name: str, spec: dict[str, object], lines: list[str], indent: str) -> None:
    nested = spec.get("__nested__", {})
    for k, v in spec.items():
        if k != "__nested__":
            lines.append(f"{indent}{k} = {v}")
    for nname, nspec in nested.items():
        lines.append("")
        lines.append(f"{indent}class {nname}:")
        for k, v in nspec.items():
            lines.append(f"{indent}    {k} = {v}")


def find_enum(pb, suffix: str):
    for name in pb.DESCRIPTOR.enum_types_by_name:
        if name == suffix:
            return pb.DESCRIPTOR.enum_types_by_name[name]
    # nested enums
    def walk(msg):
        for e in msg.enum_types:
            if e.name == suffix or e.full_name.endswith(suffix):
                return e
        for n in msg.nested_types:
            r = walk(n)
            if r is not None:
                return r
        return None
    for mname in pb.DESCRIPTOR.message_types_by_name:
        r = walk(pb.DESCRIPTOR.message_types_by_name[mname])
        if r is not None:
            return r
    raise KeyError(suffix)


def main() -> int:
    from perfetto.protos.perfetto.trace import perfetto_trace_pb2 as pb

    lines: list[str] = [
        "# generated by scripts/gen_fields.py from perfetto_trace_pb2 -- do not edit",
        "# regeneration: .venv\\Scripts\\python scripts\\gen_fields.py",
        "from __future__ import annotations",
        "",
    ]

    for msg_name, nested_spec in MESSAGES.items():
        desc = pb.DESCRIPTOR.message_types_by_name[msg_name]
        lines.append(f"class {msg_name}:")
        emit_fields(desc, nested_spec, lines, "    ")
        if msg_name == "TracePacket":
            for k, v in sorted(EXTRA_TRACE_PACKET_FIELDS.items(),
                               key=lambda kv: kv[1]):
                lines.append(f"    # missing in this pb2 version (upstream): {v}")
                lines.append(f"    {k} = {v}")
        lines.append("")
        lines.append("")

    for name, spec in EXTRA_MESSAGES.items():
        lines.append(f"# hand-transcribed: upstream perfetto proto (see gen_fields.py)")
        lines.append(f"class {name}:")
        emit_extra(name, spec, lines, "    ")
        lines.append("")
        lines.append("")

    # Enum constants.
    for prefix, suffix in ENUMS:
        enum = find_enum(pb, suffix)
        lines.append(f"# enum {enum.full_name}")
        for v in enum.values:
            lines.append(f"{prefix}{v.name} = {v.number}")
        lines.append("")

    # TRACE_PACKET_FIELD_NAMES: field number -> proto field name.
    tp = pb.TracePacket.DESCRIPTOR
    entries = {f.number: f.name for f in tp.fields}
    for k, v in EXTRA_TRACE_PACKET_FIELDS.items():
        entries[v] = k.lower()
    lines.append("TRACE_PACKET_FIELD_NAMES: dict[int, str] = {")
    for num, name in sorted(entries.items()):
        lines.append(f"    {num}: {name!r},")
    lines.append("}")
    lines.append("")

    # FTRACE_EVENT_NAMES: FtraceEvent 'event' oneof field number -> name.
    fe = pb.FtraceEvent.DESCRIPTOR
    event_oneof = fe.oneofs_by_name["event"]
    lines.append("FTRACE_EVENT_NAMES: dict[int, str] = {")
    for f in sorted(event_oneof.fields, key=lambda f: f.number):
        lines.append(f"    {f.number}: {f.name!r},")
    lines.append("}")
    lines.append("")

    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {OUT} ({len(lines)} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
