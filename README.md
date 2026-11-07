# Perfetto Trim

**English** | [简体中文](README.zh-CN.md)

A small tool that trims and splits Android Perfetto traces by time. The output
is still a standard `.perfetto-trace` file that opens directly in Perfetto UI or
trace_processor. Nothing is converted to systrace, so no data inside the window
is lost. Built for multi-GB traces: the file is processed as a stream, so memory
use does not grow with file size.

- **cut**: extract one time window.
- **split**: split into several pieces by count, duration or size, with optional overlap.
- **find**: search atrace slice names or logcat messages and cut a window around the matches.
- **info**: time range, data sources, CPUs, data-density histogram, detected app launches.

## Quick start

1. Put `perfetto-trim.exe` in any folder (no Python installation needed).
2. **Double-click it**: a console window shows the address and your browser opens
   automatically. Close the console window to quit.
3. Open a trace: paste its path into the box at the top of the page and click
   "打开" (Open), or click "选择文件" (Choose file). You can also select the file in
   Explorer, press Ctrl+Shift+C, then press Ctrl+V on an empty area of the page,
   or drag the file / folder onto the page.
4. Drag on the timeline to select a window and click "裁剪选中区间" (Cut selection).
   Output files go to the input file's folder by default.

The first time a file is opened it is scanned once (about 1.5 minutes for 1.5 GB).
The scan result is cached, so opening the same file again is instant.

> The web UI and the CLI help text are currently in Chinese.

## Web UI

- **Opening files**: the start page lists recently opened files (remove single
  entries or clear the list; files that no longer exist are greyed out).
  Browsers do not expose the real path of a dropped file, and perfetto-trim never
  uploads or copies the file. Instead it looks for the original file by name,
  size and modification time in recently used folders (and their parents),
  Downloads, Desktop and Documents. If it can't be found, paste the path with
  Ctrl+Shift+C / Ctrl+V instead; after one file from a folder has been opened,
  other files in that folder can be dropped directly. Dropping a folder lists
  the traces inside it.
- **Timeline**: bar height shows data density. Drag to select a window, drag its
  edges to adjust, mouse wheel to zoom, Shift+wheel to pan, double-click to reset.
  Keyboard: ←/→ pan, +/- zoom, Esc clears the selection. Blue bars are detected
  app launches.
- **Cut**: start and end can be typed in directly (seconds, relative to the trace
  start). The estimated size is based on the data distribution from the scan.
- **Split**: by number of parts / duration / size; split points are shown live on
  the timeline.
- **Find**: enter a keyword to list all matches. Clicking a row sets the window to
  "N seconds before and after the match" and zooms there; tick several rows to
  cut them all at once (the source file is read only once).
- **Output folder**: leave empty to write next to the input file. When done, click
  "打开输出目录" (Open output folder).

The page only listens on `127.0.0.1` and generates a random token on every launch,
so other web pages and other machines cannot call it.

## Command line

Running with arguments gives command-line mode (`perfetto-trim.exe <command> ...`).

```powershell
# Overview
perfetto-trim info trace.perfetto-trace
perfetto-trim info trace.perfetto-trace --json

# Cut: relative times (relative to the trace start)
perfetto-trim cut trace.perfetto-trace --start 12.5s --duration 10s
perfetto-trim cut trace.perfetto-trace --start 12.5s --end 22.5s -o D:\out
# Cut: the last 5 seconds; absolute timestamps (plain integers, in ns)
perfetto-trim cut trace.perfetto-trace --last 5s
perfetto-trim cut trace.perfetto-trace --start 343631134880526 --end 343641134880526

# Split
perfetto-trim split trace.perfetto-trace --parts 4
perfetto-trim split trace.perfetto-trace --every 30s --overlap 500ms
perfetto-trim split trace.perfetto-trace --size 200MB

# Find: list matches; cut match #3 / all matches (2 s before and after)
perfetto-trim find trace.perfetto-trace DrawFrames --list
perfetto-trim find trace.perfetto-trace "Choreographer#doFrame" --pick 3
perfetto-trim find trace.perfetto-trace "ANR" --source logcat -i --all --before 5s --after 5s

# Web UI (same as double-clicking)
perfetto-trim ui --port 8765 --no-browser
```

| Option | Meaning |
|---|---|
| Times | `3.5s`, `1200ms`, `800us`; a plain integer is an absolute timestamp (ns) |
| Sizes | `200MB`, `1.5GB`, `512KB` |
| `--keep-original-ts` | Keep original timestamps for carried-in state (by default it is moved to the window start so the UI has no empty lead-in) |
| `--no-cache` | Do not read or write the scan cache |
| `-j N` / `--jobs N` | Number of parsing processes, default CPU count - 1 (at most 3); `-j 1` is single-process. Output is identical for any value |
| find `--regex` / `-i` | Regex match / ignore case |
| find `--source` | `atrace`, `logcat` or `all` (default) |

## Output

- File name: `<original name>__<start ns>-<end ns>.perfetto-trace`; the timestamps are
  absolute times in the original trace. The window is half-open: `[start, end)`.
- Each run also writes a `*.report.json`: the actual window, output sizes, warnings
  and known limitations.
- `*.boundary.csv`: slices crossing the window edges (real start, end and
  duration), so you can check how long a cut slice really was.
- What is kept:
  - Metadata (trace_config, clock_snapshot, process info, stats, ...) is kept in
    every output;
  - ftrace is filtered per event; packets entirely inside the window are copied
    as-is;
  - logcat is filtered per log entry;
  - for packets on incremental clocks (sequence clocks 64..127), timestamp deltas
    are re-encoded against the packets / snapshots actually kept in the output,
    so absolute times are unchanged;
  - unknown packet types are kept whole.
- **Carried-in state**: state that already exists at the window start is added
  to the output so that Perfetto shows the same thing as for the original trace:
  the thread running on each CPU, CPU frequency / idle state, open atrace slices
  (sync, async and named tracks), current atrace counter values, binder
  transactions in flight across the boundary, the latest sys_stats / process_stats
  snapshots, process and thread names, and the process memory counters derived
  from rss_stat / rss_stat_throttled (mem.rss.*, mem.swap; not for processes that
  exited before the window start). Slices still open at the window end get an end
  event at the window end.

Correctness is checked table by table against trace_processor: sched,
thread_state, slice, counter, android_logs, frame timeline, and the trace
start/end times.

## Performance

Test machine: 12-thread CPU, 32 GB RAM; a 1.5 GB real trace (288 s, 46.7M ftrace events).

| Operation | Time | Peak memory (incl. workers) |
|---|---|---|
| First open / info (scan) | 95 s | ~380 MB |
| Cut 10 s from the middle | 85 s | ~460 MB |
| Split into 4 parts | 138 s | ~500 MB |
| Find a keyword | 110 s | ~50 MB |

Cutting with absolute timestamps needs no scan; relative times, split and find
reuse the scan cache (`%LOCALAPPDATA%\perfetto-trim\cache`). The reorder window defaults
to clamp(measured lag + 250ms, 2s, 30s) and can be overridden with
`--reorder-window`.

## Known limitations

- No filtering by process or data source (it would break data integrity).
- Chrome / App SDK track_event packets are filtered by packet timestamp (deltas
  on incremental clocks are re-encoded); track_event slices crossing the window
  edges are not carried in or closed, so slices that start before the window are lost.
- Threads that are not running (sleeping, etc.) at the window start don't have
  that state carried in; the lmk oom_score_adj counter is not carried in.
- Snapshot-type data from before the window (sys_stats, etc.) is not carried in
  if it appears very late in the file (after the output's first buffer flush).
- With `--keep-original-ts`, a few binder reply slices near the window edges may
  show as unfinished.
- trace_processor only binds rss_stat memory counters to the owning process at the
  end of parsing. For threads whose process is still unknown at the window start
  (or when one tid has several thread instances), the carried-in memory counter
  may land on another process (or on a thread-level fallback track); the value
  itself is unchanged.
- ftrace data delayed by more than 30 s in the file is handled out of order at the
  boundary (upper limit of the adaptive window).

## FAQ

- **The browser didn't open after double-clicking**: copy the full address shown in
  the console (including `#t=...`) into your browser.
- **The page says it has expired ("页面已失效")**: the token changes when the program
  restarts; use the address shown in the new console window.
- **Antivirus blocks the exe**: a single-file exe extracts itself to a temp folder
  when it runs, which some antivirus tools flag as a false positive. Add it to your
  allow list.
- **The output is larger than estimated**: each output contains its own copy of
  the metadata and carried-in state (a few MB); a single heapprofd dump cannot be split.

## Upgrading from 1.2.0 or earlier

- The exe and command were renamed from `pftrim.exe` / `pftrim` to
  `perfetto-trim.exe` / `perfetto-trim`.
- `PFTRIM_*` environment variables still work, but the new `PERFETTO_TRIM_*`
  names take precedence.
- The old cache folder `%LOCALAPPDATA%\pftrim` can be deleted.

## Development

Source layout and build, test and packaging commands are in
[`AGENTS.md`](AGENTS.md); the design notes are in [`docs/PLAN.md`](docs/PLAN.md)
(both in Chinese). One-click build (just double-click `build.bat`; it creates
`.venv`, installs dependencies, runs the tests and packages the exe):

```powershell
build.bat                # -> dist\perfetto-trim.exe
build.bat --skip-tests   # skip tests, package only
```
