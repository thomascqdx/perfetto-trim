"use strict";
// Perfetto Trim page. Times are kept as ns RELATIVE to the trace start
// (plain JS numbers, exact up to ~104 days); absolute ns go to the server
// as decimal strings built with BigInt.
(() => {
  const $ = (id) => document.getElementById(id);

  // ------------------------------------------------------------ token
  const hashTok = new URLSearchParams(location.hash.slice(1)).get("t");
  const token = hashTok || sessionStorage.getItem("pftrim-token") || "";
  if (hashTok) {
    sessionStorage.setItem("pftrim-token", hashTok);
    history.replaceState(null, "", location.pathname);
  }

  async function api(method, path, body) {
    const r = await fetch(path, {
      method,
      headers: { "X-Pftrim-Token": token, "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let data = {};
    try { data = await r.json(); } catch (_) { /* non-JSON */ }
    if (!r.ok) {
      if (r.status === 403) throw new Error("页面已失效：请从 Perfetto Trim 窗口重新打开链接。");
      throw new Error(data.error || `请求失败（HTTP ${r.status}）`);
    }
    return data;
  }

  // ------------------------------------------------------------ state
  const st = {
    path: null, info: null, startBig: 0n, end: 0,
    bins: null, prefix: null, binNs: 1e7, origin: 0, overhead: 0,
    view: [0, 1], sel: null, splitPts: [],
    matches: [], active: -1, busy: false, lastResult: null,
  };

  // ------------------------------------------------------- formatting
  function fmtBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
    return `${(n / 1073741824).toFixed(2)} GB`;
  }
  function fmtDur(ns) {
    const a = Math.abs(ns);
    if (a >= 1e9) return `${(ns / 1e9).toFixed(3)} s`;
    if (a >= 1e6) return `${(ns / 1e6).toFixed(2)} ms`;
    return `${(ns / 1e3).toFixed(1)} µs`;
  }
  const fmtSec = (ns) => (ns / 1e9).toFixed(3);
  function parseDur(s) {           // "2s" "500ms" "1.5" (seconds) -> ns
    const m = String(s).trim().match(/^(-?\d+(?:\.\d+)?)\s*(s|ms|us|µs|ns)?$/i);
    if (!m) return NaN;
    const k = { s: 1e9, ms: 1e6, us: 1e3, "µs": 1e3, ns: 1 }[(m[2] || "s").toLowerCase()];
    return Math.round(parseFloat(m[1]) * k);
  }
  function parseSize(s) {
    const m = String(s).trim().match(/^(\d+(?:\.\d+)?)\s*(b|k|kb|m|mb|g|gb)?$/i);
    if (!m) return NaN;
    const u = (m[2] || "b").toLowerCase()[0];
    return Math.round(parseFloat(m[1]) * { b: 1, k: 1024, m: 1048576, g: 1073741824 }[u]);
  }
  const absNs = (rel) => (st.startBig + BigInt(Math.round(rel))).toString();
  const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
  const baseName = (p) => p.split(/[\\/]/).pop();
  function fmtTime(ms) {
    const d = new Date(ms), p = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ` +
      `${p(d.getHours())}:${p(d.getMinutes())}`;
  }
  const looksLikePath = (s) => /^[A-Za-z]:[\\/]/.test(s) || s.startsWith("\\\\");

  // ---------------------------------------------------- data volume
  function bytesIn(a, b) {        // bytes in [a,b) rel ns, linear in bins
    if (!st.prefix || b <= a) return 0;
    const pos = (t) => {
      const x = clamp((t - st.origin) / st.binNs, 0, st.bins.length);
      const i = Math.floor(x);
      const part = i < st.bins.length ? st.bins[i] * (x - i) : 0;
      return st.prefix[i] + part;
    };
    return pos(b) - pos(a);
  }
  const estimate = (a, b) => bytesIn(a, b) + st.overhead;

  // -------------------------------------------------------- timeline
  const cv = $("tl");
  const ctx = cv.getContext("2d");
  // marker strip: launch bars y 3-7 + label baseline 18; hits y 22-32
  const TOP = 36, AXIS = 22;
  const css = getComputedStyle(document.documentElement);
  const col = (n) => css.getPropertyValue(n).trim();
  const C = { bars: col("--bars"), run: col("--run"), runFill: col("--run-fill"),
    blue: col("--runnable"), amber: col("--uninter"), ink2: col("--ink-2"),
    rule: col("--rule"), ink: col("--ink") };

  const xOf = (t, w) => (t - st.view[0]) / (st.view[1] - st.view[0]) * w;
  const tOf = (x, w) => st.view[0] + x / w * (st.view[1] - st.view[0]);

  function niceStep(span, target) {
    const raw = span / target;
    const p = Math.pow(10, Math.floor(Math.log10(raw)));
    for (const m of [1, 2, 5, 10]) if (raw <= m * p) return m * p;
    return 10 * p;
  }

  function draw() {
    const dpr = window.devicePixelRatio || 1;
    const w = cv.clientWidth, h = cv.clientHeight;
    if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(h * dpr)) {
      cv.width = Math.round(w * dpr);
      cv.height = Math.round(h * dpr);
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    if (!st.info) return;
    const y0 = TOP, y1 = h - AXIS, ph = y1 - y0;

    // density columns (sqrt scale keeps quiet stretches visible)
    const cols = Math.max(1, Math.floor(w));
    const dens = new Float64Array(cols);
    let max = 0;
    for (let i = 0; i < cols; i++) {
      const a = tOf(i, cols), b = tOf(i + 1, cols);
      const d = bytesIn(a, b) / Math.max(1, b - a);
      dens[i] = d;
      if (d > max) max = d;
    }
    const s0 = st.sel ? st.sel[0] : 0, s1 = st.sel ? st.sel[1] : 0;
    for (let i = 0; i < cols; i++) {
      if (!dens[i]) continue;
      const bh = Math.max(1, Math.sqrt(dens[i] / max) * (ph - 4));
      const t = tOf(i + 0.5, cols);
      ctx.fillStyle = st.sel && t >= s0 && t < s1 ? C.run : C.bars;
      ctx.fillRect(i * w / cols, y1 - bh, w / cols + 0.5, bh);
    }

    // selection band
    if (st.sel) {
      const xa = xOf(s0, w), xb = xOf(s1, w);
      ctx.fillStyle = C.runFill;
      ctx.fillRect(xa, y0, xb - xa, ph);
      ctx.fillStyle = C.run;
      ctx.fillRect(xa - 1, y0, 2, ph);
      ctx.fillRect(xb - 1, y0, 2, ph);
      ctx.fillRect(xa - 4, y0, 8, 10);
      ctx.fillRect(xb - 4, y0, 8, 10);
      const label = `${fmtDur(s1 - s0)}  约 ${fmtBytes(estimate(s0, s1))}`;
      ctx.font = "600 12px " + css.fontFamily;
      const tw = ctx.measureText(label).width + 12;
      const lx = clamp((xa + xb) / 2 - tw / 2, 2, w - tw - 2);
      ctx.fillStyle = "rgba(247,248,249,0.92)";
      ctx.fillRect(lx, y0 + 14, tw, 18);
      ctx.fillStyle = C.run;
      ctx.fillText(label, lx + 6, y0 + 27);
    }

    // split preview cut points
    if (st.splitPts.length) {
      ctx.fillStyle = C.blue;
      for (const p of st.splitPts) ctx.fillRect(xOf(p, w) - 1, y0, 2, ph);
    }

    // marker strip: app launches + search hits
    ctx.font = "12px " + css.fontFamily;
    for (const [t, e, label] of st.info.rel.markers) {
      const xa = xOf(t, w), xb = e == null ? xa + 2 : xOf(e, w);
      if (xb < 0 || xa > w) continue;
      ctx.fillStyle = C.blue;
      ctx.fillRect(xa, 3, Math.max(2, xb - xa), 4);
      if (xb - xa > 40) {
        ctx.fillStyle = C.ink2;
        ctx.fillText(label.slice(0, Math.floor((xb - xa) / 7)), xa + 2, 18);
      }
    }
    st.matches.forEach((m, i) => {
      const x = xOf(m.rel_ns, w);
      if (x < -2 || x > w + 2) return;
      ctx.fillStyle = C.amber;
      if (i === st.active) ctx.fillRect(x - 1.5, 22, 3, y1 - 22);
      else ctx.fillRect(x - 0.5, 22, 1.5, 10);
    });

    // axis (seconds from trace start)
    ctx.fillStyle = C.rule;
    ctx.fillRect(0, y1, w, 1);
    const span = st.view[1] - st.view[0];
    const step = niceStep(span, Math.max(2, w / 110));
    ctx.fillStyle = C.ink2;
    ctx.font = "12px " + css.fontFamily;
    for (let t = Math.ceil(st.view[0] / step) * step; t <= st.view[1]; t += step) {
      const x = xOf(t, w);
      ctx.fillRect(x, y1, 1, 5);
      const dec = step >= 1e9 ? 0 : step >= 1e8 ? 1 : step >= 1e7 ? 2 : 3;
      ctx.fillText(`${(t / 1e9).toFixed(dec)} s`, x + 3, h - 6);
    }
  }

  // drag / zoom
  let drag = null;
  const EDGE = 6;
  function hit(x, w) {
    if (!st.sel) return null;
    if (Math.abs(x - xOf(st.sel[0], w)) <= EDGE) return "a";
    if (Math.abs(x - xOf(st.sel[1], w)) <= EDGE) return "b";
    return null;
  }
  cv.addEventListener("pointerdown", (e) => {
    if (!st.info || e.button !== 0) return;
    const w = cv.clientWidth, x = e.offsetX;
    const t = clamp(tOf(x, w), 0, st.end);
    const edge = hit(x, w);
    drag = edge ? { edge } : { anchor: t, moved: false };
    if (!edge) st.sel = [t, t];
    cv.setPointerCapture(e.pointerId);
  });
  cv.addEventListener("pointermove", (e) => {
    const w = cv.clientWidth;
    if (!drag) {
      cv.style.cursor = hit(e.offsetX, w) ? "ew-resize" : "crosshair";
      return;
    }
    const t = clamp(tOf(e.offsetX, w), 0, st.end);
    if (drag.edge === "a") st.sel = [Math.min(t, st.sel[1]), st.sel[1]];
    else if (drag.edge === "b") st.sel = [st.sel[0], Math.max(t, st.sel[0])];
    else { drag.moved = true; st.sel = [Math.min(drag.anchor, t), Math.max(drag.anchor, t)]; }
    syncSel();
  });
  cv.addEventListener("pointerup", () => {
    if (drag && !drag.edge && st.sel &&
        xOf(st.sel[1], cv.clientWidth) - xOf(st.sel[0], cv.clientWidth) < 3) {
      st.sel = null;          // a click, not a drag
    }
    drag = null;
    syncSel();
  });
  function zoom(factor, center) {
    const [a, b] = st.view;
    let span = clamp((b - a) * factor, 1e6, st.end);
    let na = center - (center - a) * span / (b - a);
    na = clamp(na, 0, st.end - span);
    st.view = [na, na + span];
    draw();
  }
  cv.addEventListener("wheel", (e) => {
    if (!st.info) return;
    e.preventDefault();
    const w = cv.clientWidth;
    if (e.shiftKey || Math.abs(e.deltaX) > Math.abs(e.deltaY)) {
      const d = (e.deltaX || e.deltaY) / w * (st.view[1] - st.view[0]);
      pan(d);
    } else {
      zoom(e.deltaY > 0 ? 1.25 : 0.8, tOf(e.offsetX, w));
    }
  }, { passive: false });
  function pan(d) {
    const span = st.view[1] - st.view[0];
    const a = clamp(st.view[0] + d, 0, st.end - span);
    st.view = [a, a + span];
    draw();
  }
  cv.addEventListener("dblclick", () => { st.view = [0, st.end]; draw(); });
  cv.addEventListener("keydown", (e) => {
    if (!st.info) return;
    const span = st.view[1] - st.view[0];
    const mid = (st.view[0] + st.view[1]) / 2;
    if (e.key === "ArrowLeft") pan(-span * 0.1);
    else if (e.key === "ArrowRight") pan(span * 0.1);
    else if (e.key === "+" || e.key === "=") zoom(0.8, mid);
    else if (e.key === "-") zoom(1.25, mid);
    else if (e.key === "Escape") { st.sel = null; syncSel(); }
    else return;
    e.preventDefault();
  });
  new ResizeObserver(draw).observe(cv);

  // ------------------------------------------------------ cut panel
  function syncSel() {
    if (st.sel) {
      $("cut-start").value = fmtSec(st.sel[0]);
      $("cut-end").value = fmtSec(st.sel[1]);
      $("cut-dur").textContent = fmtDur(st.sel[1] - st.sel[0]);
      $("cut-size").textContent = "约 " + fmtBytes(estimate(st.sel[0], st.sel[1]));
    } else {
      $("cut-dur").textContent = "–";
      $("cut-size").textContent = "–";
    }
    draw();
  }
  function selFromInputs() {
    const a = parseDur($("cut-start").value), b = parseDur($("cut-end").value);
    if (Number.isFinite(a) && Number.isFinite(b) && b > a) {
      st.sel = [clamp(a, 0, st.end), clamp(b, 0, st.end)];
      syncSel();
    }
  }
  $("cut-start").addEventListener("change", selFromInputs);
  $("cut-end").addEventListener("change", selFromInputs);
  $("panel-cut").addEventListener("submit", (e) => {
    e.preventDefault();
    // re-parse the inputs only if the user edited them -- otherwise a
    // dragged selection would be rounded to the 3-decimal text.
    if (!st.sel || $("cut-start").value !== fmtSec(st.sel[0]) ||
        $("cut-end").value !== fmtSec(st.sel[1])) selFromInputs();
    if (!st.sel || st.sel[1] <= st.sel[0]) return showError("请先在时间轴上选择区间，或填写起点和终点。");
    runJob(api("POST", "/api/cut", {
      path: st.path, start_ns: absNs(st.sel[0]),
      // [S, E): selecting through the trace end must include the last event
      end_ns: st.sel[1] >= st.end
        ? (st.startBig + BigInt(Math.round(st.end)) + 1n).toString()
        : absNs(st.sel[1]),
      keep_original_ts: $("cut-keep").checked, out_dir: $("out-dir").value,
    }));
  });

  // ---------------------------------------------------- split panel
  const splitMode = () => document.querySelector("input[name=split-mode]:checked").value;
  const SPLIT_UI = {
    parts: ["份数", "4", "按数据量均分，切点显示在时间轴上。"],
    every: ["每段时长", "10s", "每段固定时长，如 10s、500ms。"],
    size: ["每段大小", "200MB", "按数据量切到目标大小附近，如 200MB。"],
  };
  document.querySelectorAll("input[name=split-mode]").forEach((r) =>
    r.addEventListener("change", () => {
      const [lbl, v, note] = SPLIT_UI[splitMode()];
      $("split-value-label").firstChild.textContent = lbl;
      $("split-value").value = v;
      $("split-note").textContent = note;
      previewSplit();
    }));
  $("split-value").addEventListener("input", previewSplit);

  function equalPoints(k) {       // mirrors ops/split.py _cut_points
    const total = st.prefix[st.bins.length], target = total / k, pts = [];
    let acc = 0, nxt = target;
    for (let i = 0; i < st.bins.length && pts.length < k - 1; i++) {
      acc += st.bins[i];
      while (acc >= nxt && pts.length < k - 1) {
        pts.push(st.origin + (i + 1) * st.binNs);
        nxt += target;
      }
    }
    return pts;
  }
  function previewSplit() {
    st.splitPts = [];
    if (!st.info || $("panel-split").hidden) { draw(); return; }
    const v = $("split-value").value, mode = splitMode();
    let note = SPLIT_UI[mode][2];
    if (mode === "parts") {
      const k = parseInt(v, 10);
      if (k >= 2 && k <= 1000) st.splitPts = equalPoints(k);
    } else if (mode === "every") {
      const d = parseDur(v);
      if (d > 0 && st.end / d <= 1000) for (let t = d; t < st.end; t += d) st.splitPts.push(t);
    } else {
      const s = parseSize(v);
      const timed = st.prefix[st.bins.length];
      if (s > st.overhead) {
        const k = Math.ceil(timed / (s - st.overhead));
        if (k >= 2 && k <= 1000) st.splitPts = equalPoints(k);
      } else if (s > 0) note = `目标大小需大于每段固定开销（约 ${fmtBytes(st.overhead)}）。`;
    }
    if (st.splitPts.length) {
      const n = st.splitPts.length + 1;
      note = `将切成 ${n} 段，每段约 ${fmtBytes(st.prefix[st.bins.length] / n + st.overhead)}。`;
    }
    $("split-note").textContent = note;
    draw();
  }
  $("panel-split").addEventListener("submit", (e) => {
    e.preventDefault();
    runJob(api("POST", "/api/split", {
      path: st.path, mode: splitMode(), value: $("split-value").value,
      overlap: $("split-overlap").value, keep_original_ts: $("split-keep").checked,
      out_dir: $("out-dir").value,
    }));
  });

  // ----------------------------------------------------- find panel
  $("find-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const res = await runJob(api("POST", "/api/find", {
      path: st.path, pattern: $("find-pattern").value,
      source: $("find-source").value, regex: $("find-regex").checked,
      ignore_case: $("find-icase").checked,
    }), { quiet: true });
    if (res) showMatches(res);
  });
  function showMatches(res) {
    st.matches = res.matches;
    st.active = -1;
    $("find-results").hidden = false;
    $("find-count").textContent = res.matches.length
      ? `${res.matches.length} 条匹配${res.truncated ? "（已达上限，只显示前面的）" : ""}`
      : "没有匹配。换个关键字，或勾选“忽略大小写”。";
    const body = $("find-body");
    body.textContent = "";
    res.matches.forEach((m, i) => {
      const tr = document.createElement("tr");
      tr.dataset.i = i;
      const dur = m.end_rel_ns != null ? fmtDur(m.end_rel_ns - m.rel_ns) : "–";
      tr.innerHTML = `<td><input type="checkbox" aria-label="选择第 ${i + 1} 条"></td>
        <td>${fmtSec(m.rel_ns)} s</td><td>${dur}</td>
        <td><span class="src"></span></td><td></td>`;
      tr.querySelector(".src").textContent = m.source;
      tr.lastElementChild.textContent = m.name;
      body.appendChild(tr);
    });
    $("find-all").checked = false;
    draw();
  }
  function matchWindow(m) {
    const before = parseDur($("find-before").value) || 0;
    const after = parseDur($("find-after").value) || 0;
    const end = m.end_rel_ns != null ? m.end_rel_ns : m.rel_ns;
    return [clamp(m.rel_ns - before, 0, st.end), clamp(end + after, 0, st.end)];
  }
  $("find-body").addEventListener("click", (e) => {
    const tr = e.target.closest("tr");
    if (!tr || e.target.matches("input")) return;
    const i = +tr.dataset.i;
    st.active = i;
    document.querySelectorAll("#find-body tr.active").forEach((r) => r.classList.remove("active"));
    tr.classList.add("active");
    st.sel = matchWindow(st.matches[i]);
    const pad = (st.sel[1] - st.sel[0]) * 1.5 + 1e6;
    const a = clamp(st.sel[0] - pad, 0, st.end), b = clamp(st.sel[1] + pad, 0, st.end);
    st.view = [a, Math.max(b, a + 1e6)];
    syncSel();
  });
  $("find-all").addEventListener("change", (e) =>
    document.querySelectorAll("#find-body input").forEach((c) => { c.checked = e.target.checked; }));
  $("find-cut").addEventListener("click", () => {
    const idx = [...document.querySelectorAll("#find-body tr")]
      .filter((tr) => tr.querySelector("input").checked).map((tr) => +tr.dataset.i);
    if (!idx.length) return showError("先勾选要截取的匹配。");
    runJob(api("POST", "/api/cut_many", {
      path: st.path, pattern: $("find-pattern").value, out_dir: $("out-dir").value,
      windows: idx.map((i) => matchWindow(st.matches[i]).map(absNs)),
    }));
  });

  // ----------------------------------------------------------- tabs
  const tabs = ["cut", "split", "find"];
  function selectTab(name, focus) {
    for (const t of tabs) {
      const on = t === name;
      const b = $(`tab-${t}`);
      b.setAttribute("aria-selected", on);
      b.tabIndex = on ? 0 : -1;
      $(`panel-${t}`).hidden = !on;
      if (on && focus) b.focus();
    }
    if (name === "split") previewSplit(); else { st.splitPts = []; draw(); }
  }
  tabs.forEach((t, i) => {
    const b = $(`tab-${t}`);
    b.addEventListener("click", () => selectTab(t));
    b.addEventListener("keydown", (e) => {
      const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
      if (d) selectTab(tabs[(i + d + tabs.length) % tabs.length], true);
    });
  });

  // ----------------------------------------------------------- jobs
  function setBusy(b) {
    st.busy = b;
    for (const id of ["cut-go", "split-go", "find-go", "find-cut", "open-btn", "pick"]) $(id).disabled = b;
  }
  function showError(msg) {
    $("status").hidden = false;
    $("task-error").hidden = false;
    $("task-error").textContent = msg;
  }
  function clearStatus() {
    $("task-error").hidden = true;
    $("status").hidden = $("task-run").hidden;
  }
  let currentJob = null;
  $("task-cancel").addEventListener("click", () => {
    if (currentJob) api("POST", `/api/jobs/${currentJob}/cancel`).catch(() => {});
  });

  // start promise -> poll -> result (null on error/cancel)
  async function runJob(startPromise, opts = {}) {
    if (st.busy) return null;
    setBusy(true);
    $("task-error").hidden = true;
    if (!opts.quiet) { $("task-done").hidden = true; $("task-idle").hidden = true; }
    $("status").hidden = false;
    $("task-run").hidden = false;
    $("task-bar").style.width = "0%";
    $("task-stage").textContent = "准备中";
    try {
      let job = await startPromise;
      currentJob = job.id;
      while (job.state === "running") {
        await new Promise((r) => setTimeout(r, 400));
        job = await api("GET", `/api/jobs/${job.id}`);
        $("task-bar").style.width = `${(job.progress * 100).toFixed(1)}%`;
        $("task-stage").textContent = `${job.stage || "处理中"} ${(job.progress * 100).toFixed(0)}%`;
      }
      if (job.state === "cancelled") { showError("已取消，没有生成输出文件。"); return null; }
      if (job.state === "error") { showError(job.error); return null; }
      if (job.result && job.result.outputs) showOutputs(job.result);
      return job.result;
    } catch (err) {
      showError(err.message);
      return null;
    } finally {
      currentJob = null;
      $("task-run").hidden = true;
      $("status").hidden = $("task-error").hidden;
      setBusy(false);
    }
  }
  function showOutputs(res) {
    st.lastResult = res;
    const ul = $("task-outputs");
    ul.textContent = "";
    for (const o of res.outputs) {
      const li = document.createElement("li");
      const fn = document.createElement("span");
      fn.className = "fn";
      fn.textContent = baseName(o.path);
      const meta = document.createElement("span");
      meta.className = "meta";
      const s = Number(BigInt(o.start_ns) - st.startBig), e = Number(BigInt(o.end_ns) - st.startBig);
      meta.textContent = `${fmtBytes(o.bytes)}，${fmtSec(s)}–${fmtSec(e)} s`;
      li.append(fn, meta);
      ul.appendChild(li);
    }
    for (const w of res.warnings || []) {
      const li = document.createElement("li");
      li.className = "warn";
      li.textContent = `提示：${w}`;
      ul.appendChild(li);
    }
    $("task-done").hidden = false;
  }
  $("task-open").addEventListener("click", () => {
    if (st.lastResult) api("POST", "/api/open_dir", { path: st.lastResult.out_dir }).catch((e) => showError(e.message));
  });

  // ------------------------------------------------------ open file
  function renderFacts(info) {
    const f = $("facts");
    f.textContent = "";
    const add = (label, value, cls) => {
      const s = document.createElement("span");
      if (cls) { s.className = cls; s.textContent = value; } else {
        s.append(`${label} `);
        const b = document.createElement("b");
        b.textContent = value;
        s.appendChild(b);
      }
      f.appendChild(s);
    };
    add("", baseName(st.path), "name");
    add("大小", fmtBytes(info.file_size));
    add("时长", fmtDur(info.rel.end));
    add("CPU", String(Object.keys(info.ftrace.per_cpu || {}).length));
    const types = Object.entries(info.per_type).sort((a, b) => b[1].bytes - a[1].bytes)
      .slice(0, 4).map(([k]) => k).join("，");
    add("主要数据", types || "–");
    const nw = Object.keys(info.warnings || {}).length;
    if (nw) add("警告", `${nw} 项`);
  }
  async function openTrace(path) {
    if (!path) return;
    $("path").value = path;
    const info = await runJob(api("POST", "/api/open", { path }), { quiet: true });
    if (!info) return;
    st.path = path;
    st.info = info;
    st.startBig = BigInt(info.start_ns_str);
    st.end = Math.max(1, info.rel.end);
    st.bins = info.hist_bin_bytes;
    st.binNs = info.hist_bin_ns;
    st.origin = info.rel.hist_origin;
    st.overhead = info.overhead_bytes;
    st.prefix = new Float64Array(st.bins.length + 1);
    for (let i = 0; i < st.bins.length; i++) st.prefix[i + 1] = st.prefix[i] + st.bins[i];
    st.view = [0, st.end];
    st.sel = null;
    st.matches = [];
    st.active = -1;
    $("find-results").hidden = true;
    $("empty").hidden = true;
    $("workspace").hidden = false;
    $("task-idle").hidden = false;
    $("task-done").hidden = true;
    clearStatus();
    document.title = `${baseName(path)} - Perfetto Trim`;
    renderFacts(info);
    syncSel();
    previewSplit();
    loadRecent();
  }
  $("open-form").addEventListener("submit", (e) => {
    e.preventDefault();
    openTrace($("path").value.trim().replace(/^"|"$/g, ""));
  });
  $("pick").addEventListener("click", async () => {
    try {
      const r = await api("POST", "/api/pick", {});
      if (r.path) openTrace(r.path);
    } catch (err) { showError(err.message); }
  });

  function renderRecent(recent) {
    const dl = $("recent-list");
    dl.textContent = "";
    for (const e of recent) {
      const o = document.createElement("option");
      o.value = e.path;
      dl.appendChild(o);
    }
    $("recent-block").hidden = !recent.length;
    const cards = $("recent-cards");
    cards.textContent = "";
    for (const e of recent) {
      const li = document.createElement("li");
      if (!e.exists) li.className = "missing";
      const b = document.createElement("button");
      b.type = "button";
      b.className = "recent-open";
      b.title = e.path;
      if (e.exists) b.addEventListener("click", () => openTrace(e.path));
      else b.disabled = true;
      const name = document.createElement("span");
      name.className = "r-name";
      name.textContent = e.name;
      const meta = document.createElement("span");
      meta.className = "r-meta";
      meta.textContent = e.exists
        ? [e.dir, e.size == null ? null : fmtBytes(e.size),
           e.mtime_ms == null ? null : fmtTime(e.mtime_ms)]
          .filter((s) => s).join(" · ")
        : "文件不存在";
      b.append(name, meta);
      const rm = document.createElement("button");
      rm.type = "button";
      rm.className = "recent-rm";
      rm.textContent = "×";
      rm.title = "从最近记录移除";
      rm.setAttribute("aria-label", "从最近记录移除");
      rm.addEventListener("click", async (ev) => {
        ev.stopPropagation();
        try {
          const r = await api("POST", "/api/recent/remove", { path: e.path });
          renderRecent(r.recent);
        } catch (err) { showError(err.message); }
      });
      li.append(b, rm);
      cards.appendChild(li);
    }
  }
  async function loadRecent() {
    try {
      const { recent } = await api("GET", "/api/recent");
      renderRecent(recent);
    } catch (err) {
      $("recent-block").hidden = false;
      $("recent-cards").innerHTML = "";
      const li = document.createElement("li");
      li.className = "error";
      li.textContent = err.message;
      $("recent-cards").appendChild(li);
    }
  }
  $("recent-clear").addEventListener("click", async () => {
    try {
      const r = await api("POST", "/api/recent/clear", {});
      renderRecent(r.recent);
    } catch (err) { showError(err.message); }
  });

  // ------------------------------------------- open by paste / drop
  document.addEventListener("paste", (e) => {
    const el = e.target;
    if (el instanceof Element &&
        (el.closest("input, textarea, select") || el.isContentEditable)) return;
    const text = e.clipboardData && e.clipboardData.getData("text/plain");
    if (!text) return;
    const line = text.split(/\r?\n/).map((l) => l.trim()).find((l) => l);
    if (!line) return;
    const path = line.replace(/^"|"$/g, "");
    if (!looksLikePath(path)) return;
    e.preventDefault();
    openTrace(path);
  });

  const overlay = $("drop-overlay");
  const TRACE_EXT = /\.(perfetto-trace|pftrace|trace|gz)$/i;
  const DROP_HINT = "在资源管理器选中它按 Ctrl+Shift+C，再回到本页 Ctrl+V。";
  let dragDepth = 0;
  const hasFiles = (e) =>
    e.dataTransfer && [...e.dataTransfer.types].includes("Files");
  window.addEventListener("dragenter", (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    if (dragDepth++ === 0) overlay.hidden = false;
  });
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("dragleave", (e) => {
    if (!hasFiles(e)) return;
    if (--dragDepth <= 0) { dragDepth = 0; overlay.hidden = true; }
  });
  window.addEventListener("drop", (e) => {
    e.preventDefault();
    dragDepth = 0;
    overlay.hidden = true;
    handleDrop(e.dataTransfer);
  });

  function readDir(reader) {
    return new Promise((res) => {
      const all = [];
      const step = () => reader.readEntries((batch) => {
        if (!batch.length) return res(all);
        all.push(...batch);
        step();
      }, () => res(all));
      step();
    });
  }
  async function collectDropped(dt) {
    const out = [];
    const addFile = (file, rel) => {
      if (out.length < 200 && TRACE_EXT.test(file.name)) {
        out.push({ rel, size: file.size, mtime_ms: file.lastModified });
      }
    };
    const entries = [];
    for (const item of dt.items) {
      const en = item.webkitGetAsEntry && item.webkitGetAsEntry();
      if (en) entries.push(en);
    }
    if (entries.length) {
      const walk = async (en) => {
        if (en.isFile) {
          const f = await new Promise((res, rej) => en.file(res, rej));
          addFile(f, en.fullPath.replace(/^\//, ""));
        } else if (en.isDirectory) {
          for (const c of await readDir(en.createReader())) await walk(c);
        }
      };
      for (const en of entries) await walk(en);
    } else {
      for (const f of dt.files) addFile(f, f.name);
    }
    return out;
  }
  function showPickDialog(items) {
    const dlg = $("pick-trace"), ul = $("pick-list");
    ul.textContent = "";
    let unlocated = 0;
    for (const it of [...items].sort((a, b) => a.rel.localeCompare(b.rel))) {
      const li = document.createElement("li");
      const b = document.createElement("button");
      b.type = "button";
      const rn = document.createElement("span");
      rn.className = "r-name";
      rn.textContent = it.rel;
      const rm = document.createElement("span");
      rm.className = "r-meta";
      rm.textContent = it.path
        ? `${fmtBytes(it.size)} · ${fmtTime(it.mtime_ms)}`
        : `未找到路径 · ${fmtBytes(it.size)} · ${fmtTime(it.mtime_ms)}`;
      if (it.path) {
        b.title = it.path;
        b.addEventListener("click", () => { dlg.close(); openTrace(it.path); });
      } else {
        b.disabled = true;
        unlocated++;
      }
      b.append(rn, rm);
      li.appendChild(b);
      ul.appendChild(li);
    }
    $("pick-note").hidden = !unlocated;
    dlg.showModal();
  }
  $("pick-cancel").addEventListener("click", () => $("pick-trace").close());
  async function handleDrop(dt) {
    if (!dt) return;
    if (!dt.files.length) {
      const txt = (dt.getData("text/plain") || "")
        .trim().replace(/^"|"$/g, "");
      if (looksLikePath(txt)) openTrace(txt);
      return;
    }
    let items;
    try {
      items = await collectDropped(dt);
    } catch (err) {
      return showError(`读取拖入内容失败：${err.message || err}`);
    }
    if (!items.length) {
      return showError("没有找到 trace 文件（.perfetto-trace / .pftrace / .trace / .gz）");
    }
    try {
      const { paths } = await api("POST", "/api/locate", {
        items: items.map(({ rel, size, mtime_ms }) => ({ rel, size, mtime_ms })),
      });
      items.forEach((it, i) => { it.path = paths[i]; });
    } catch (err) {
      return showError(err.message);
    }
    if (items.length === 1) {
      const it = items[0];
      if (it.path) return openTrace(it.path);
      showError(`找不到「${it.rel}」在本机的位置（浏览器拖放拿不到文件路径）。${DROP_HINT}`);
      $("path").focus();
      return;
    }
    showPickDialog(items);
  }

  loadRecent();
})();
