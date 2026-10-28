"""
Streamlit SOC console (preloaded) for the Cybersecurity Threat Intelligence Platform Solution.

`render_app(...)` builds the whole console from the callbacks main.py injects — running an organization
through the flow, reading the four agents' assessments and the final report, and (when a critical incident
is flagged) approving or rejecting the incident-response plan as a human SOC analyst (HITL).

Launch from the Project folder with:
    python3 -m streamlit run main.py
"""

from core.config import (STATUS_PROCESSING, STATUS_REVIEW, STATUS_STYLES,
                         config)  # keep as FIRST project import (telemetry bootstrap)

import html
import json
from pathlib import Path

import streamlit as st

_CSS = """
<style>
  section.main > div.block-container { padding-top: 1.2rem; max-width: 1200px; }
  #MainMenu, footer { visibility: hidden; }
  .app-header { background: linear-gradient(100deg,#b91c1c 0%,#991b1b 55%,#7f1d1d 100%);
      border-radius: 16px; padding: 1.3rem 1.6rem; margin-bottom: 1.2rem; color: #fee2e2; }
  .app-title { font-size: 1.6rem; font-weight: 800; letter-spacing:-.01em; }
  .app-sub { font-size: .9rem; opacity: .92; margin-top: .2rem; color:#fecaca; }
  .content-bar { display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap;
      gap:.5rem; margin: .2rem 0 1rem; }
  .c-id { font-size:1.2rem; font-weight:800; color:#0f172a; }
  .c-type { color:#b91c1c; font-weight:700; font-size:.8rem; background:#fee2e2; padding:.15rem .55rem;
      border-radius:999px; margin-left:.4rem; text-transform:uppercase; letter-spacing:.04em; }
  .c-rid { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; color:#94a3b8; font-size:.78rem; }
  .meta-strip { display:flex; flex-wrap:wrap; gap:.45rem; margin:-.3rem 0 1.1rem; }
  .meta { background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:.3rem .6rem; font-size:.8rem; }
  .meta-l { color:#94a3b8; text-transform:uppercase; letter-spacing:.04em; font-size:.6rem;
      font-weight:800; margin-right:.4rem; }
  .meta-v { color:#0f172a; font-weight:600; }
  .status { border-radius:12px; padding:.8rem 1.1rem; font-size:.95rem; border-left:6px solid; margin-bottom:1rem; }
  .status .lab { font-weight:800; letter-spacing:.02em; }
  .status.ok  { background:#f0fdf4; border-color:#16a34a; color:#166534; }
  .status.warn{ background:#fffbeb; border-color:#d97706; color:#92400e; }
  .status.bad { background:#fef2f2; border-color:#dc2626; color:#991b1b; }
  .status.info{ background:#eff6ff; border-color:#2563eb; color:#1e40af; }
  .kpi { background:#fff; border:1px solid #e2e8f0; border-radius:14px; padding:.95rem 1.05rem;
      box-shadow:0 1px 2px rgba(15,23,42,.04); height:100%; }
  .kpi-val { font-size:1.7rem; font-weight:800; color:#0f172a; line-height:1.1; }
  .kpi-lbl { font-size:.68rem; text-transform:uppercase; letter-spacing:.07em; color:#64748b;
      font-weight:700; margin-top:.15rem; }
  .bar { height:6px; background:#e2e8f0; border-radius:999px; margin-top:.55rem; overflow:hidden; }
  .bar > span { display:block; height:100%; border-radius:999px; }
  .card { background:#fff; border:1px solid #e2e8f0; border-radius:14px; padding:1.05rem 1.2rem;
      box-shadow:0 1px 2px rgba(15,23,42,.04); margin-bottom:.9rem; color:#334155; }
  .sec { font-size:.72rem; text-transform:uppercase; letter-spacing:.08em; color:#b91c1c;
      font-weight:800; margin:.2rem 0 .55rem; }
  .badge { display:inline-block; border-radius:6px; padding:.1rem .5rem; font-size:.68rem;
      font-weight:800; text-transform:uppercase; letter-spacing:.04em; margin-right:.4rem; }
  .badge.critical, .badge.immediate { background:#fee2e2; color:#b91c1c; }
  .badge.high, .badge.urgent { background:#ffe4e6; color:#be123c; }
  .badge.medium { background:#fef3c7; color:#a16207; }
  .badge.low, .badge.informational { background:#dcfce7; color:#15803d; }
  .finding { border:1px solid #e2e8f0; border-radius:10px; padding:.65rem .9rem; margin-bottom:.55rem;
      background:#fff; color:#334155; }
  .finding .rec { color:#64748b; font-size:.85rem; margin-top:.25rem; }
  .pipeline { display:flex; flex-wrap:wrap; gap:.55rem; margin:.1rem 0 1.2rem; }
  .stage { display:flex; align-items:center; gap:.4rem; border:1px solid #e2e8f0; border-radius:10px;
      padding:.45rem .85rem; background:#fff; font-weight:700; font-size:.85rem; color:#0f172a; }
  .stage-mark { font-weight:800; } .stage-time { color:#94a3b8; font-weight:600; font-size:.76rem; }
  .stage.done { border-color:#bbf7d0; } .stage.done .stage-mark { color:#16a34a; }
  .stage.err { border-color:#fecaca; background:#fef2f2; } .stage.err .stage-mark { color:#dc2626; }
  .stage.skip { opacity:.5; } .stage.skip .stage-mark { color:#94a3b8; }
  .hitl-outcome { border-radius:12px; padding:.8rem 1.1rem; margin-top:1.2rem; border-left:6px solid;
      font-size:.95rem; } .hitl-outcome .lab { font-weight:800; }
  .hitl-outcome.ok { background:#f0fdf4; border-color:#16a34a; color:#166534; }
  .hitl-outcome.bad { background:#fef2f2; border-color:#dc2626; color:#991b1b; }
  .recent { padding:.4rem 0; font-size:.85rem; color:#334155; border-bottom:1px solid #f1f5f9; }
  .dot { width:9px; height:9px; border-radius:50%; display:inline-block; margin-right:.35rem; }
  .recent-status { color:#94a3b8; font-size:.72rem; text-transform:uppercase; letter-spacing:.04em; }
  .side-h { font-size:.7rem; text-transform:uppercase; letter-spacing:.08em; color:#64748b;
      font-weight:800; margin:.6rem 0 .3rem; }
  .empty { text-align:center; color:#64748b; padding:4rem 1rem; border:2px dashed #e2e8f0;
      border-radius:16px; background:#fff; font-size:1rem; }
  .footer-ts { text-align:center; color:#94a3b8; font-size:.75rem; margin-top:1.4rem;
      border-top:1px solid #f1f5f9; padding-top:.7rem; }
</style>
"""

_STATE_CLASS = {"success": "ok", "warning": "warn", "error": "bad", "info": "info"}
_DOT_COLOR = {"success": "#22c55e", "warning": "#d97706", "error": "#dc2626", "info": "#2563eb"}


def render_app(run_threat_intelligence, approve_response, reject_response, list_intel):
    """Render the SOC console; the four callbacks come from main.py."""
    st.set_page_config(page_title="Threat Intelligence Platform", layout="wide")
    st.markdown(_CSS, unsafe_allow_html=True)

    if "record" not in st.session_state:
        st.session_state.record = None

    st.markdown(
        '<div class="app-header"><div class="app-title">Cybersecurity Threat Intelligence Platform</div>'
        '<div class="app-sub">CrewAI Flow &nbsp;·&nbsp; threat detection &rarr; analysis &rarr; incident '
        'response &rarr; security recommendations (with human review of critical incidents)</div></div>',
        unsafe_allow_html=True)

    with st.sidebar:
        st.markdown('<div class="side-h">Assess an organization</div>', unsafe_allow_html=True)
        store_path = Path(config.data_dir) / "threat_store.json"
        orgs = []
        if store_path.exists():
            orgs = list(json.loads(store_path.read_text(encoding="utf-8")).get("organizations", {}).keys())
        choice = st.selectbox("Organization", orgs or ["(no organizations found)"],
                              label_visibility="collapsed")
        if st.button("Run threat intelligence", type="primary", use_container_width=True, disabled=not orgs):
            with st.spinner("Running the CrewAI flow (this calls Gemini)…"):
                try:
                    st.session_state.record = run_threat_intelligence(choice)
                except Exception as error:
                    st.session_state.record = None
                    st.error(f"Run failed: {error}")
        st.markdown('<div class="side-h">Recent runs</div>', unsafe_allow_html=True)
        history = list_intel(10)
        if not history:
            st.caption("No runs yet.")
        for past in history:
            method = STATUS_STYLES.get(past.get("status", ""), ("info", ""))[0]
            st.markdown(
                f'<div class="recent"><span class="dot" style="background:{_DOT_COLOR[method]}"></span>'
                f'<b>{html.escape(str(past.get("organization", "")))}</b> · '
                f'{html.escape(str(past.get("response_mode", "") or "-"))}<br>'
                f'<span class="recent-status">{html.escape(str(past.get("status", "")))}</span></div>',
                unsafe_allow_html=True)

    record = st.session_state.record
    if not record:
        st.markdown('<div class="empty">Pick an organization in the sidebar and click '
                    '<b>Run threat intelligence</b> to assess it.</div>', unsafe_allow_html=True)
        return

    status = record.get("status", STATUS_PROCESSING)
    method, message = STATUS_STYLES.get(status, ("info", status))
    mode = str(record.get("response_mode", "") or "-").upper()
    st.markdown(
        f'<div class="content-bar"><div><span class="c-id">'
        f'{html.escape(str(record.get("organization", "")))}</span>'
        f'<span class="c-type">{html.escape(mode)} mode</span></div>'
        f'<div class="c-rid">{html.escape(str(record.get("record_id", "")))}</div></div>',
        unsafe_allow_html=True)

    tdata = record.get("threat_data", {}) or {}
    meta_items = [("Threats", len(tdata.get("threats", []) or []) or None),
                  ("Frameworks", "NIST · CIS · MITRE")]
    meta_chips = "".join(
        f'<span class="meta"><span class="meta-l">{html.escape(lbl)}</span>'
        f'<span class="meta-v">{html.escape(str(val))}</span></span>'
        for lbl, val in meta_items if val is not None)
    if meta_chips:
        st.markdown(f'<div class="meta-strip">{meta_chips}</div>', unsafe_allow_html=True)

    st.markdown(
        f'<div class="status {_STATE_CLASS[method]}"><span class="lab">'
        f'{html.escape(status.replace("_", " ").title())}</span> &nbsp;—&nbsp; {html.escape(message)}</div>',
        unsafe_allow_html=True)

    errors = record.get("errors", []) or []
    if errors:
        messages = "; ".join(html.escape(str(e.get("message", e))) for e in errors)
        st.markdown(f'<div class="status bad"><span class="lab">Agent errors</span> &nbsp;—&nbsp; '
                    f'{messages}</div>', unsafe_allow_html=True)

    severity = float(record.get("threat_severity_score", 0.0) or 0.0)
    critical = int(record.get("critical_threats", 0) or 0)
    compromised = int(record.get("compromised_systems", 0) or 0)
    rec_count = int(record.get("recommendations_count", 0) or 0)
    confidence = float(record.get("confidence", 0.0) or 0.0)
    duration = record.get("metrics", {}).get("total_seconds", 0)
    kpi = st.columns(4)
    kpi[0].markdown(f'<div class="kpi"><div class="kpi-val">{severity:.0f}<span style="font-size:.9rem">/100'
                    f'</span></div><div class="kpi-lbl">Threat severity</div><div class="bar"><span '
                    f'style="width:{max(0, min(100, severity)):.0f}%;'
                    f'background:{"#dc2626" if severity >= 70 else "#d97706" if severity >= 40 else "#22c55e"}">'
                    f'</span></div></div>', unsafe_allow_html=True)
    kpi[1].markdown(f'<div class="kpi"><div class="kpi-val" style="color:{"#dc2626" if critical else "#0f172a"}">'
                    f'{critical}</div><div class="kpi-lbl">Critical threats</div></div>', unsafe_allow_html=True)
    kpi[2].markdown(f'<div class="kpi"><div class="kpi-val" style="color:{"#dc2626" if compromised else "#0f172a"}">'
                    f'{compromised}</div><div class="kpi-lbl">Compromised systems</div></div>',
                    unsafe_allow_html=True)
    kpi[3].markdown(f'<div class="kpi"><div class="kpi-val" style="font-size:1.25rem;padding-top:.35rem">'
                    f'{html.escape(mode)}</div><div class="kpi-lbl">Response &middot; {rec_count} recs '
                    f'&middot; conf {confidence:.2f}</div></div>', unsafe_allow_html=True)
    st.write("")

    analyses = record.get("agent_analyses", {}) or {}
    metrics = record.get("metrics", {}) or {}
    stage_chips = []
    for stage_label, stage_key in (("Detection", "detector"), ("Analysis", "analyst"),
                                   ("Response", "responder"), ("Recommendations", "advisor")):
        entry = analyses.get(stage_key)
        if entry is None:
            stage_cls, mark = "skip", "&#9675;"
        elif entry.get("status") == "error":
            stage_cls, mark = "err", "&#10007;"
        else:
            stage_cls, mark = "done", "&#10003;"
        secs = metrics.get(stage_key)
        time_html = f'<span class="stage-time">{secs}s</span>' if secs is not None else ""
        stage_chips.append(f'<div class="stage {stage_cls}"><span class="stage-mark">{mark}</span>'
                           f'<span>{html.escape(stage_label)}</span>{time_html}</div>')
    st.markdown(f'<div class="sec">Pipeline trace</div><div class="pipeline">'
                f'{"".join(stage_chips)}</div>', unsafe_allow_html=True)

    report_tab, threats_tab, response_tab, rec_tab = st.tabs(
        ["  Report  ", "  Threats  ", "  Response  ", "  Recommendations  "])

    with report_tab:
        rationale = str(record.get("rationale", "")).strip()
        if rationale:
            st.markdown(f'<div class="card"><div class="sec">Analyst rationale</div>'
                        f'{html.escape(rationale)}</div>', unsafe_allow_html=True)
        st.markdown(record.get("report") or "_No report was generated for this run._")

    with threats_tab:
        analysis = record.get("threat_analysis", {}) or {}
        if tdata.get("summary"):
            st.markdown(f'<div class="card"><div class="sec">Detection summary</div>'
                        f'{html.escape(str(tdata["summary"]))}</div>', unsafe_allow_html=True)
        if analysis.get("summary"):
            st.markdown(f'<div class="card"><div class="sec">Analysis summary</div>'
                        f'{html.escape(str(analysis["summary"]))}</div>', unsafe_allow_html=True)
        for threat in (tdata.get("threats", []) or []):
            sev = str(threat.get("severity", "medium")).lower()
            sev = sev if sev in ("critical", "high", "medium", "low", "informational") else "medium"
            cat = html.escape(str(threat.get("category", "threat")))
            vec = html.escape(str(threat.get("vector", "")))
            src = html.escape(str(threat.get("source", "")))
            st.markdown(f'<div class="finding"><span class="badge {sev}">{sev}</span><b>{cat}</b>'
                        f'<div class="rec">{vec}{" &middot; source: " + src if src else ""}</div></div>',
                        unsafe_allow_html=True)
        for actor in (analysis.get("threat_actors", []) or []):
            name = html.escape(str(actor.get("name", "")))
            atype = html.escape(str(actor.get("type", "")))
            motive = html.escape(str(actor.get("motivation", "")))
            st.markdown(f'<div class="finding"><div class="sec">Threat actor</div><b>{name}</b>'
                        f'<div class="rec">{atype} &middot; {motive}</div></div>', unsafe_allow_html=True)
        for pattern in (analysis.get("attack_patterns", []) or []):
            tech = html.escape(str(pattern.get("technique", "")))
            tactic = html.escape(str(pattern.get("tactic", "")))
            desc = html.escape(str(pattern.get("description", "")))
            st.markdown(f'<div class="finding"><b>{tech}</b><div class="rec">tactic: {tactic}'
                        f'{" &middot; " + desc if desc else ""}</div></div>', unsafe_allow_html=True)
        impact = analysis.get("business_impact", {}) or {}
        if impact:
            items = " &nbsp;·&nbsp; ".join(f'{html.escape(k.replace("_", " "))}: <b>{html.escape(str(v))}</b>'
                                           for k, v in impact.items())
            st.markdown(f'<div class="sec" style="margin-top:.4rem">Business impact</div>'
                        f'<div class="finding">{items}</div>', unsafe_allow_html=True)
        if not tdata.get("threats") and not analysis:
            st.caption("No threats surfaced for this run.")

    with response_tab:
        summary = str(record.get("containment_summary", "")).strip()
        if summary:
            st.markdown(f'<div class="card"><div class="sec">Containment summary ({html.escape(mode)} mode)'
                        f'</div>{html.escape(summary)}</div>', unsafe_allow_html=True)
        for action in (record.get("response_actions", []) or []):
            pr = str(action.get("priority", "medium")).lower()
            pr = pr if pr in ("critical", "immediate", "high", "urgent", "medium", "low") else "medium"
            phase = html.escape(str(action.get("phase", "")))
            act = html.escape(str(action.get("action", "")))
            target = html.escape(str(action.get("target", "")))
            st.markdown(f'<div class="finding"><span class="badge {pr}">{pr}</span><b>{phase}</b>'
                        f'<div class="rec">{act}</div><div class="rec">target: {target}</div></div>',
                        unsafe_allow_html=True)
        forensics = record.get("forensic_findings", []) or []
        if forensics:
            st.markdown('<div class="sec" style="margin-top:.5rem">Forensic findings</div>',
                        unsafe_allow_html=True)
            for f in forensics:
                ev = html.escape(str(f.get("evidence", "")))
                finding = html.escape(str(f.get("finding", "")))
                st.markdown(f'<div class="finding"><b>{ev}</b><div class="rec">{finding}</div></div>',
                            unsafe_allow_html=True)
        if not record.get("response_actions"):
            st.caption("No incident-response plan for this run.")

    with rec_tab:
        for rec in (record.get("security_recommendations", []) or []):
            pr = str(rec.get("priority", "medium")).lower()
            pr = pr if pr in ("critical", "high", "medium", "low") else "medium"
            cat = html.escape(str(rec.get("category", "control")))
            control = html.escape(str(rec.get("control", "")))
            text = html.escape(str(rec.get("recommendation", "")))
            st.markdown(f'<div class="finding"><span class="badge {pr}">{pr}</span><b>{cat} &middot; '
                        f'{control}</b><div class="rec">{text}</div></div>', unsafe_allow_html=True)
        roadmap = record.get("roadmap", []) or []
        if roadmap:
            st.markdown('<div class="sec" style="margin-top:.5rem">Security roadmap</div>',
                        unsafe_allow_html=True)
            for item in roadmap:
                init = html.escape(str(item.get("initiative", "")))
                extra = " · ".join(str(item.get(k, "")) for k in ("timeframe", "effort", "roi") if item.get(k))
                st.markdown(f'<div class="finding"><b>{init}</b><div class="rec">{html.escape(extra)}</div>'
                            f'</div>', unsafe_allow_html=True)
        if not record.get("security_recommendations"):
            st.caption("No security recommendations for this run.")

    hitl = record.get("hitl", {}) or {}
    if hitl.get("decision"):
        outcome = str(hitl.get("decision"))
        outcome_cls = "ok" if "approv" in outcome.lower() else "bad"
        reviewer_note = html.escape(str(hitl.get("reviewer_note") or "—"))
        st.markdown(f'<div class="hitl-outcome {outcome_cls}"><span class="lab">SOC analyst '
                    f'{html.escape(outcome.upper())}</span> &nbsp;—&nbsp; note: {reviewer_note}</div>',
                    unsafe_allow_html=True)
    elif status == STATUS_REVIEW:
        st.markdown('<div class="sec" style="margin-top:1.3rem">Human review — critical incident</div>',
                    unsafe_allow_html=True)
        st.markdown('<div class="status warn"><span class="lab">Needs a human</span> &nbsp;—&nbsp; '
                    'this organization has a critical incident; a SOC analyst must approve or reject the '
                    'incident-response plan (containment actions) before it is executed.</div>',
                    unsafe_allow_html=True)
        note = st.text_input("Reviewer note", placeholder="Add a note for the audit trail…")
        approve_col, reject_col, _ = st.columns([1, 1, 3])
        if approve_col.button("Approve response", type="primary", use_container_width=True):
            st.session_state.record = approve_response(record, note or "Approved by SOC analyst")
            st.rerun()
        if reject_col.button("Reject response", use_container_width=True):
            st.session_state.record = reject_response(record, note or "Rejected by SOC analyst")
            st.rerun()

    created = str(record.get("created_at", "") or "")[:19].replace("T", " ")
    resolved = str(record.get("resolved_at", "") or "")[:19].replace("T", " ")
    st.markdown(f'<div class="footer-ts">created {html.escape(created)} &nbsp;&rarr;&nbsp; '
                f'resolved {html.escape(resolved) or "—"} &nbsp;·&nbsp; {duration}s total</div>',
                unsafe_allow_html=True)
