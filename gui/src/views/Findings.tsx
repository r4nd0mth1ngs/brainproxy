import { useEffect, useMemo, useRef, useState } from "react";
import { bodyText, historyRequest, isBinary, MAX_BODY, rawResponse, run, inTauri, type Finding, type FindingEvent, type FindingItem, type HistoryEntry, type Risk } from "../api";
import { originOf, useApp } from "../store";
import { ask, confirm } from "../ui/Confirm";
import { Menu, type MenuItem, useMenu } from "../ui/Menu";
import { chooseSave } from "../ui/chooseSave.ts";
import { saveFailure } from "../ui/savePath.ts";
import { HttpView } from "../ui/HttpView";
import { Split } from "../ui/Split";
import { usePoll } from "../ui/usePoll";
import { useActions } from "../ui/useActions.ts";
import { compareArgs, seenById, type ScanCompare, type ScanJob, type Seen } from "./compare";
import {
  CLOSED,
  eventText,
  type FindingFilter,
  narrativeCommand,
  narrativeCredit,
  suggestionText,
  type Narrative,
  type Trail,
  trailLine,
  groupKey,
  hostsOf,
  inView,
  type ListView,
  markCommands,
  NO_FILTER,
  noteBy,
  noteCommand,
  recordTicketCommand,
  reproCommand,
  retestCommand,
  riskCounts,
  SOURCES,
  type Source,
  STATES,
  type Ticket,
  ticketCommand,
  ticketLinkProblem,
  ticketText,
  type Tracker,
} from "./findingsFilter";
import {
  acceptCommand,
  afterMark,
  dismissedKey,
  draftOf,
  dropDraft,
  NEXT_FINDING,
  parseDismissed,
  pendingSuggestions,
  PREVIOUS_FINDING,
  stepFinding,
  TRIAGE_KEYS,
  withDismissed,
  withDraft,
} from "./findingsTriage.ts";
import { heldNote, loadAll, type ListPage, type Loaded } from "./findingsPages.ts";
import { CvssDialog, MergeDialog, SplitDialog } from "./IssueDialogs";
import { cvssLabel, issueActionProblems, type IssueInfo, issueMap, issuesArgs, pickedActions, titleCommand } from "./issueTools.ts";
import { addedBy } from "./manualFinding";
import { isScriptAnswer, SCRIPT_ANSWER_NOTE } from "./matchReplace.ts";
import { openVerifyDiff, verifyFinding, VerifyStrip } from "./PayloadCompare.tsx";
import { findingRanges, type FindingRanges, payloadMarks } from "./payloadMarks.ts";
import type { Verify } from "./verifyFinding.ts";
import { NewFinding } from "./NewFinding";
import { ReportBuilder } from "./ReportBuilder";

const RISKS: Risk[] = ["critical", "high", "medium", "low", "info"];
const NO_RANGES: FindingRanges = { ranges: [], marked: null };
const RANK: Record<Risk, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const LIVE_STATES = STATES.map((s) => s.id).join(",");

type Compare = "all" | Seen;
/** The issue dialog open now, if any. */
type IssueDialogState = { kind: "cvss"; issue: IssueInfo } | { kind: "merge"; from: IssueInfo[]; targets: IssueInfo[] } | { kind: "split"; issue: IssueInfo } | null;
const COMPARE: { id: Compare; label: string; title: string }[] = [
  { id: "all", label: "All findings", title: "Every finding in the project" },
  { id: "new", label: "New in", title: "First found by this scan" },
  { id: "still", label: "Still found by", title: "Found before and found again by this scan" },
  {
    id: "gone",
    label: "Not found again by",
    title: "Found before, but this scan covered the site and rule and didn't find it again: likely fixed. Passive findings count only when the scan crawled.",
  },
];

export function RiskBadge({ risk }: { risk: Risk }) {
  return <span className={`risk risk-${risk}`}>{risk}</span>;
}

/** An issue: one alert type on one host, with the findings it was seen at. */
interface Group {
  key: string;
  alert: string;
  /** The alert's name, as its first finding has it. */
  name: string;
  /** The issue's own title where it has one, else `name`. */
  title: string;
  issue: IssueInfo | undefined;
  host: string;
  risk: Risk;
  items: FindingItem[];
}

export function FindingsView({ active }: { active: boolean }) {
  const app = useApp();
  // Every triage state but removed: removed findings added by hand stay in the project for
  // comparisons, not in the list. Read in pages, so a big project isn't cut short unseen.
  // With the issues' titles and CVSS ratings, which the findings list doesn't carry; read
  // together, so a merge or split shows in both at once.
  const [data, refresh] = usePoll<Loaded & { issues: IssueInfo[] }>(async () => {
    const [list, i] = await Promise.all([loadAll((args) => run<ListPage>(args), LIVE_STATES), run<{ issues: IssueInfo[] }>(issuesArgs(LIVE_STATES))]);
    return { ...list, issues: i.issues };
  }, 5000, active);
  const issues = useMemo(() => issueMap(data?.issues), [data]);
  const issueTitles = useMemo(() => new Map([...issues.values()].filter((i) => i.titled).map((i) => [i.id, i.title])), [issues]);
  const [issueDialog, setIssueDialog] = useState<IssueDialogState>(null);
  const [risks, setRisks] = useState(new Set<Risk>(RISKS));
  const [hideFp, setHideFp] = useState(true);
  const [filter, setFilter] = useState<FindingFilter>(NO_FILTER);
  // Findings ticked for bulk triage; only the ones still shown are acted on.
  const [checked, setChecked] = useState(new Set<number>());
  const [busy, setBusy] = useState(false);
  // Unsaved notes by finding and write-ups by issue: opening another finding keeps them.
  const [noteDrafts, setNoteDrafts] = useState<ReadonlyMap<number, string>>(new Map());
  const [writeupDrafts, setWriteupDrafts] = useState<ReadonlyMap<number, string>>(new Map());
  const [open, setOpen] = useState(new Set<string>());
  const [selected, setSelected] = useState<number | null>(null);
  const [finding, setFinding] = useState<Finding | null>(null);
  // The finding open now, for a triage that finishes after another one was picked.
  const openId = useRef(selected);
  openId.current = selected;
  const [entry, setEntry] = useState<HistoryEntry | null>(null);
  const [events, setEvents] = useState<FindingEvent[]>([]);
  // The issue's write-up and the agent trail of the open finding.
  const [narrative, setNarrative] = useState<Narrative | null>(null);
  // The issue `narrative` is the write-up of. A finding moved to another issue (a merge or a
  // split) shows no write-up until that issue's arrives, so the old one is never saved onto it.
  const [narrativeIssue, setNarrativeIssue] = useState<number | null>(null);
  const narrativeFor = useRef<number | null>(null);
  const [trail, setTrail] = useState<Trail | null>(null);
  const [retesting, setRetesting] = useState(false);
  // The finding added by hand being edited, as it was when the dialog opened.
  const [editing, setEditing] = useState<Finding | null>(null);
  // The finding sent with and without its payload, for the finding it was run on.
  const [verified, setVerified] = useState<Verify | null>(null);
  const [verifying, setVerifying] = useState(false);
  // Compare with a scan: what's new, still there, or no longer found (likely fixed).
  const [compare, setCompare] = useState<Compare>("all");
  const [scanId, setScanId] = useState<number | null>(null);
  const [jobs] = usePoll<{ jobs: (ScanJob & { kind: string; state: string })[] }>(() => run(["job", "list", "--limit", "100"]), 10000, active);
  const scans = useMemo(() => (jobs?.jobs ?? []).filter((j) => j.kind === "active-scan" && (j.state === "completed" || j.state === "stopped")), [jobs]);
  const scan = scans.find((j) => j.id === scanId) ?? scans[0];
  const [compared, refreshSeen] = usePoll<ScanCompare | null>(
    () => (scan && compare !== "all" ? run<ScanCompare>(compareArgs(scan.id)) : Promise.resolve(null)),
    5000,
    active && compare !== "all",
  );
  useEffect(refreshSeen, [scan?.id, compare, refreshSeen]);
  const seen = useMemo(() => seenById(compared), [compared]);
  const comparing = compare !== "all" && scan != null;

  const view = useMemo<ListView>(() => ({ hideClosed: hideFp, filter, compare: comparing ? { seen, want: compare } : null, issueTitles }), [hideFp, filter, comparing, seen, compare, issueTitles]);
  const groups = useMemo(() => {
    const by = new Map<string, Group>();
    for (const f of data?.items ?? []) {
      if (!risks.has(f.risk) || !inView(f, view)) continue;
      const key = groupKey(f);
      const issue = f.issue_id != null ? issues.get(f.issue_id) : undefined;
      const g = by.get(key) ?? { key, alert: f.alert_ref, name: f.name, title: issue?.title ?? f.name, issue, host: f.host, risk: f.risk, items: [] };
      if (RANK[f.risk] < RANK[g.risk]) g.risk = f.risk;
      g.items.push(f);
      by.set(key, g);
    }
    return [...by.values()].sort((a, b) => RANK[a.risk] - RANK[b.risk] || a.title.localeCompare(b.title));
  }, [data, risks, view, issues]);

  const hosts = useMemo(() => hostsOf(data?.items ?? []), [data]);
  const byId = useMemo(() => new Map((data?.items ?? []).map((f) => [f.id, f])), [data]);
  const shown = useMemo(() => groups.flatMap((g) => g.items.map((f) => f.id)), [groups]);
  const picked = useMemo(() => shown.filter((id) => checked.has(id)), [shown, checked]);
  const filtering = filter.text !== "" || filter.source !== "all" || filter.host !== "";

  // As the list would show each risk: the same filters, a hidden risk counted as if shown.
  const counts = useMemo(() => riskCounts(data?.items ?? [], view), [data, view]);

  useEffect(() => {
    if (selected == null) return;
    let live = true;
    setEntry(null);
    setVerified(null);
    setEvents([]);
    setNarrative(null);
    setNarrativeIssue(null);
    narrativeFor.current = null;
    setTrail(null);
    run<{ events: FindingEvent[] }>(["findings", "timeline", String(selected)]).then((t) => live && setEvents(t.events), () => {});
    run<Trail>(["findings", "trail", String(selected)]).then((t) => live && setTrail(t), () => {});
    run<Finding>(["findings", "show", String(selected)])
      .then((f) => {
        if (!live) return;
        setFinding(f);
        if (f.issue_id != null) loadNarrative(f.issue_id, () => live);
        shownEntry.current = null;
        loadEntry(f.history_id, () => live);
      })
      .catch((e) => app.toast(e.message, "error"));
    return () => {
      live = false;
    };
  }, [selected, app.toast]);

  const added = (id: number, ref: string, warnings: string[]) => {
    app.newFinding(null);
    app.toast([`Finding #${id} added.`, ...warnings].join("\n"));
    setRisks(new Set(RISKS));
    setCompare("all");
    // Its issue's group opens once the finding says which issue that is.
    run<Finding>(["findings", "show", String(id)]).then(
      (f) => setOpen((o) => new Set(o).add(groupKey(f))),
      () => setOpen((o) => new Set(o).add(`alert:${ref}`)),
    );
    setSelected(id);
    refresh();
  };

  // An edit keeps the finding's id: it is read again, with its timeline, if it is still open.
  const edited = (id: number, changed: string[], warnings: string[]) => {
    setEditing(null);
    app.toast([changed.length ? `Finding #${id} edited.` : `Finding #${id} unchanged.`, ...warnings].join("\n"));
    if (openId.current === id) {
      run<Finding>(["findings", "show", String(id)]).then((f) => openId.current === id && setFinding(f), () => {});
      reloadEvents(id);
    }
    refresh();
  };

  // An agent's suggestions: the person accepts one (as their own mark, only while the finding
  // is still in the state on screen) or dismisses it. Dismissals are this window's to remember.
  const dismissKey = dismissedKey(app.project);
  const [dismissed, setDismissed] = useState<ReadonlySet<number>>(() => readDismissed(dismissKey));
  useEffect(() => setDismissed(readDismissed(dismissKey)), [dismissKey]);
  const suggestions = useMemo(() => pendingSuggestions(events, dismissed), [events, dismissed]);
  const dismiss = (s: FindingEvent) => {
    const { set, text } = withDismissed(dismissed, s.id);
    setDismissed(set);
    try {
      localStorage.setItem(dismissKey, text);
    } catch {
      /* storage unavailable: dismissed until the app restarts */
    }
  };
  const accept = async (s: FindingEvent) => {
    if (!finding) return;
    const id = finding.id;
    const cmd = acceptCommand(id, s, finding.state);
    if (!cmd) return dismiss(s);
    if (s.text && finding.note && finding.note !== s.text) {
      const ok = await confirm("Replace the note?", `The finding's note becomes the agent's: "${s.text}". The note it has now stays on its timeline.`, "Replace it", "Cancel");
      if (!ok) return;
    }
    try {
      await run(cmd);
    } catch (e: any) {
      app.toast(e.message, "error");
    }
    if (openId.current === id) reloadDetail(id);
    refresh();
  };

  // Only findings added by hand can be removed; scanner findings are marked instead.
  const remove = async () => {
    if (!finding) return;
    const message = `"${finding.name}" at ${finding.url} leaves the findings and reports. The project keeps a record that it was removed, so comparing with an earlier report shows it as removed, not fixed.`;
    if (!(await confirm("Remove this finding?", message, "Remove", "Keep"))) return;
    try {
      await run(["findings", "remove", String(finding.id)]);
      setSelected(null);
      setFinding(null);
      setEntry(null);
      refresh();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  // An issue's write-up, unless another finding (or another issue of this one) was opened meanwhile.
  const loadNarrative = (issue: number, live: () => boolean = () => true) => {
    narrativeFor.current = issue;
    return run<{ narrative: Narrative | null }>(["findings", "issue", "show", String(issue)]).then(
      (i) => {
        if (!live() || narrativeFor.current !== issue) return;
        setNarrative((cur) => (same(cur, i.narrative) ? cur : i.narrative));
        setNarrativeIssue(issue);
      },
      () => {},
    );
  };

  // The recorded request and response, read again only when the finding points at another one.
  const shownEntry = useRef<number | null>(null);
  const loadEntry = (history: number | null, live: () => boolean) => {
    if (history != null && history === shownEntry.current) return;
    shownEntry.current = history;
    if (history == null) return setEntry(null);
    run<HistoryEntry>(["history", "show", String(history), MAX_BODY]).then(
      (e) => live() && setEntry(e),
      () => {
        if (shownEntry.current === history) shownEntry.current = null;
      },
    );
  };

  // The open finding as it is now: the list's poll brings changes made elsewhere (an agent, a
  // rescan, a retest, a bulk mark), and the detail follows. Drafts are kept apart, so they stay.
  const eventsRef = useRef(events);
  eventsRef.current = events;
  const reloadDetail = (id: number) => {
    const live = () => openId.current === id;
    run<Finding>(["findings", "show", String(id)]).then((f) => {
      if (!live()) return;
      setFinding((cur) => (same(cur, f) ? cur : f));
      if (narrativeFor.current !== f.issue_id) {
        setNarrative(null);
        setNarrativeIssue(null);
        narrativeFor.current = null;
      }
      if (f.issue_id != null) loadNarrative(f.issue_id, live);
      loadEntry(f.history_id, live);
    }, () => {});
    run<{ events: FindingEvent[] }>(["findings", "timeline", String(id)]).then((t) => {
      if (!live() || same(eventsRef.current, t.events)) return;
      const grew = eventsRef.current.length !== t.events.length;
      setEvents(t.events);
      if (grew) run<Trail>(["findings", "trail", String(id)]).then((tr) => live() && setTrail(tr), () => {});
    }, () => {});
  };
  // The attack in the request pane: its payload, located against the request the scan started
  // from where there is one, else the parameter it was found in (payloadMarks.ts).
  const [reqRanges, setReqRanges] = useState<FindingRanges>(NO_RANGES);
  const attack = finding?.attack ?? "";
  const param = finding?.param ?? "";
  const baseId = finding?.base_history_id ?? null;
  useEffect(() => {
    setReqRanges(NO_RANGES);
    if (!entry || isBinary(entry.request)) return;
    let live = true;
    const raw = bodyText(entry.request);
    const base = attack && baseId != null ? historyRequest(baseId).then((b) => (b.binary ? null : b.raw), () => null) : Promise.resolve(null);
    base.then((b) => live && setReqRanges(findingRanges(raw, attack, param, b)));
    return () => {
      live = false;
    };
  }, [entry, attack, param, baseId]);

  // Only on a poll: opening a finding reads it in full (above).
  useEffect(() => {
    if (selected != null && finding?.id === selected) reloadDetail(selected);
  }, [data]);

  const noteDraft = finding ? draftOf(noteDrafts, finding.id, finding.note ?? "") : "";
  const writeup = finding?.issue_id != null ? draftOf(writeupDrafts, finding.issue_id, narrative?.text ?? "") : "";
  const setNoteDraft = (text: string) => {
    if (finding) setNoteDrafts((d) => withDraft(d, finding.id, text, finding.note ?? ""));
  };
  const setWriteup = (text: string) => {
    const issue = finding?.issue_id;
    if (issue != null) setWriteupDrafts((d) => withDraft(d, issue, text, narrative?.text ?? ""));
  };

  const saveWriteup = async (review: boolean) => {
    const issue = finding?.issue_id;
    const id = finding?.id;
    if (issue == null || id == null || narrativeIssue !== issue) return;
    const sent = writeup;
    try {
      if (!review) {
        await run(narrativeCommand(issue, sent));
        setWriteupDrafts((d) => dropDraft(d, issue, sent));
      }
      // The review names the text on screen; one changed since (by an agent, say) is refused.
      else await run(["findings", "issue", "review", String(issue), `--hash=${narrative?.hash ?? ""}`]);
      // Another finding opened meanwhile keeps its own write-up.
      if (openId.current === id) loadNarrative(issue, () => openId.current === id);
    } catch (e: any) {
      app.toast(e.message, "error");
      if (openId.current === id) loadNarrative(issue, () => openId.current === id);
    }
  };

  // A ticket's title and body in the tracker's markup, ready to paste (nothing is sent).
  const ticketMenu = useMenu();
  const trackerName = (t: Tracker) => (t === "jira" ? "Jira" : "GitHub");
  const copyTicket = async (tracker: Tracker) => {
    if (!finding) return;
    try {
      const t = await run<Ticket>(ticketCommand(finding.id, tracker));
      await navigator.clipboard.writeText(ticketText(t, tracker));
      app.toast(`Ticket copied: paste it into a ${trackerName(tracker)} issue. Secrets are masked.`);
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  // The link of a ticket the person filed, kept on the finding's timeline and in reports.
  const recordTicket = async (tracker: Tracker) => {
    if (!finding) return;
    const id = finding.id;
    const url = await ask(`Record a ${trackerName(tracker)} ticket`, "The link of the ticket you filed for this finding. Reports and the timeline show it.", "Record", "Cancel");
    if (url == null) return;
    const problem = ticketLinkProblem(url);
    if (problem) return app.toast(problem, "error");
    try {
      await run(recordTicketCommand(id, tracker, url));
      app.toast("Ticket recorded.");
      if (openId.current === id) reloadEvents(id);
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  // A repro pack as a JSON file: the request with secrets masked, a curl command, the response
  // around the evidence, what the rule looks for and the command that checks it again.
  const saveRepro = async () => {
    if (!finding) return;
    const id = finding.id;
    let chosen: { path: string; overwrite: boolean } | null = null;
    try {
      chosen = await chooseSave(`finding-${id}-repro.json`, "JSON", "json");
      if (!chosen) return;
      await run(reproCommand(id, chosen.path, chosen.overwrite));
      app.toast(`Repro pack saved to ${chosen.path}. Secrets are masked.`);
      if (inTauri) {
        const { revealItemInDir } = await import("@tauri-apps/plugin-opener");
        await revealItemInDir(chosen.path).catch(() => {});
      }
    } catch (e: any) {
      app.toast(chosen ? saveFailure(e, chosen.path) : e.message, "error");
    }
  };

  // The open finding's timeline, again after a change to it.
  const reloadEvents = (id: number) =>
    run<{ events: FindingEvent[] }>(["findings", "timeline", String(id)]).then((t) => openId.current === id && setEvents(t.events), () => {});

  // Opens a finding, and its group so it shows in the list.
  const select = (id: number | null) => {
    if (id == null) return;
    const f = byId.get(id);
    if (f) setOpen((o) => (o.has(groupKey(f)) ? o : new Set(o).add(groupKey(f))));
    setSelected(id);
  };

  // `advance`: then the next finding opens (from the keyboard), unless another was opened meanwhile.
  const mark = async (state: string, advance = false) => {
    if (!finding) return;
    const id = finding.id;
    const next = advance ? afterMark(shown, id) : null;
    try {
      await run(["findings", "mark", String(id), "--state", state]);
      setFinding((cur) => (cur?.id === id ? { ...cur, state } : cur));
      if (advance && openId.current === id && next != null) select(next);
      else reloadEvents(id);
      refresh();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  // Sends the finding's request again; one that may change data is sent only once confirmed.
  const retest = async () => {
    if (!finding) return;
    const id = finding.id;
    setRetesting(true);
    try {
      let r: { outcome: string; state: string };
      try {
        r = await run(retestCommand(id));
      } catch (e: any) {
        if (!/--allow-unsafe/.test(e.message)) throw e;
        const ok = await confirm("Send this request again?", `${e.message.replace(/; pass --allow-unsafe.*$/, "")}.`, "Send it", "Cancel");
        if (!ok) return;
        r = await run(retestCommand(id, true));
      }
      app.toast(r.outcome === "still_present" ? `Still there: finding #${id} is ${r.state.replace("_", " ")}.` : `Not reproduced: finding #${id} is now ${r.state.replace("_", " ")}.`);
      if (openId.current === id) setFinding((cur) => (cur?.id === id ? { ...cur, state: r.state } : cur));
      reloadEvents(id);
      refresh();
    } catch (e: any) {
      app.toast(e.message, "error");
    } finally {
      setRetesting(false);
    }
  };

  // Sends the request the scan started from and the attack again, and shows how they differ.
  const verify = async () => {
    if (!finding) return;
    const id = finding.id;
    setVerifying(true);
    try {
      const v = await verifyFinding(id);
      if (v && openId.current === id) setVerified(v);
    } catch (e: any) {
      app.toast(e.message, "error");
    } finally {
      setVerifying(false);
    }
  };

  // The attack, with its payload highlighted: located against the request the scan started
  // from where there is one (payloadMarks.ts).
  const sendToReplay = async () => {
    if (!finding || !entry) return;
    const f = finding;
    try {
      const { raw, binary } = await historyRequest(entry.id);
      let base: string | null = null;
      if (f.base_history_id != null && !binary) base = await historyRequest(f.base_history_id).then((b) => (b.binary ? null : b.raw), () => null);
      const marks = binary ? [] : payloadMarks(raw, f.attack, base);
      app.sendToRepeater({
        raw,
        binary,
        target: originOf(entry.url),
        title: f.name.slice(0, 24),
        ...(marks.length ? { marks } : {}),
        ...(canVerify(f) && entry.id === f.history_id ? { finding: f.id } : {}),
      });
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  // Several findings at once, in batches; a failed batch stops there and says so.
  const markPicked = async (state: string) => {
    setBusy(true);
    let done = 0;
    try {
      for (const cmd of markCommands(picked, state)) {
        await run(cmd);
        done += cmd.length - 4;
      }
      app.toast(`Marked ${done} finding${done === 1 ? "" : "s"} ${state.replace("_", " ")}.`);
      setChecked(new Set());
      setFinding((cur) => (cur && picked.includes(cur.id) ? { ...cur, state } : cur));
    } catch (e: any) {
      app.toast(`${done ? `Marked ${done}, then: ` : ""}${e.message}`, "error");
    }
    setBusy(false);
    // The open finding's timeline gets the mark, even when only some batches went through.
    if (openId.current != null && picked.includes(openId.current)) reloadDetail(openId.current);
    refresh();
  };

  const saveNote = async () => {
    if (!finding) return;
    const id = finding.id;
    const sent = noteDraft;
    try {
      await run(noteCommand(id, sent));
      setNoteDrafts((d) => dropDraft(d, id, sent));
      const f = await run<Finding>(["findings", "show", String(id)]);
      // Another finding was opened meanwhile: the note is saved, and that one is shown.
      if (openId.current !== id) return;
      setFinding(f);
      reloadEvents(id);
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  // Issues rearranged (renamed, rated, merged, split): the list, the issues and the open
  // finding are read again, and `show` (an issue the findings moved to) opens in the list.
  const issueChanged = (show?: number) => {
    setIssueDialog(null);
    if (show != null) setOpen((o) => new Set(o).add(`issue:${show}`));
    refresh();
    if (openId.current != null) reloadDetail(openId.current);
  };
  const retitle = async (issue: IssueInfo, title: string) => {
    try {
      await run(titleCommand(issue.id, title));
      issueChanged();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };
  const renameIssue = async (issue: IssueInfo) => {
    const title = await ask(`Rename issue #${issue.id}`, "Its title in Findings and in reports, in place of the alert's name. Reset title goes back to the alert's name.", "Rename", "Cancel", issue.title);
    if (title != null && title.trim() !== issue.title) retitle(issue, title);
  };
  // From an issue's menu: into any other issue the list has.
  const mergeIssue = (issue: IssueInfo) => setIssueDialog({ kind: "merge", from: [issue], targets: [...issues.values()].filter((i) => i.id !== issue.id) });
  // From ticked findings (those shown): merge their issues, or split them off theirs.
  const pickedFor = useMemo(() => pickedActions(picked, byId, issues), [picked, byId, issues]);
  const issueMenuItems = (issue: IssueInfo): (MenuItem | "-")[] => {
    const no = issueActionProblems(issue, issues.size);
    return [
      { label: "Rename issue…", action: () => renameIssue(issue), hint: issue.titled ? `Now “${issue.title}”` : undefined },
      ...(issue.titled ? [{ label: "Reset title", action: () => retitle(issue, ""), hint: "Back to the alert's name" }] : []),
      { label: "CVSS rating…", action: () => setIssueDialog({ kind: "cvss", issue }), hint: cvssLabel(issue) || "Not rated" },
      "-",
      { label: "Merge into…", action: () => mergeIssue(issue), disabled: !!no.merge, hint: no.merge || "Move its findings into another issue" },
      { label: "Split…", action: () => setIssueDialog({ kind: "split", issue }), disabled: !!no.split, hint: no.split || "Move some of its findings to a new issue" },
    ];
  };
  const issueMenu = useMenu();
  const openIssue = finding?.issue_id != null ? issues.get(finding.issue_id) : undefined;

  // The report builder: audience, sections, branding, format, with a preview.
  const [reporting, setReporting] = useState(false);
  const reportName = app.temp ? "engagement" : app.project.split(/[\\/]/).pop()!.replace(/\.bpdb$/, "");
  const noFinding: string | false = finding ? false : "No finding is open";
  const noList: string | false = shown.length ? false : "No findings are shown";
  const noIssue: string | false = noFinding || (openIssue ? false : "The open finding has no issue");
  useActions([
    { ...NEXT_FINDING, hidden: !active, disabled: noList, run: () => select(stepFinding(shown, selected, 1)) },
    { ...PREVIOUS_FINDING, hidden: !active, disabled: noList, run: () => select(stepFinding(shown, selected, -1)) },
    ...TRIAGE_KEYS.map((k) => ({ ...k, hidden: !active, disabled: noFinding, run: () => mark(k.state, true) })),
    { id: "findings.new", title: "New finding…", group: "Findings", keywords: "write up manual issue", run: () => app.newFinding({}) },
    { id: "findings.issue.rename", title: "Rename issue…", group: "Findings", keywords: "title retitle", hidden: !active, disabled: noIssue, run: () => openIssue && renameIssue(openIssue) },
    { id: "findings.issue.cvss", title: "Issue CVSS rating…", group: "Findings", keywords: "cvss 4.0 vector score severity rate", hidden: !active, disabled: noIssue, run: () => openIssue && setIssueDialog({ kind: "cvss", issue: openIssue }) },
    {
      id: "findings.issue.merge",
      title: "Merge issue into…",
      group: "Findings",
      keywords: "combine join",
      hidden: !active,
      disabled: noIssue || (openIssue && issueActionProblems(openIssue, issues.size).merge) || false,
      run: () => openIssue && mergeIssue(openIssue),
    },
    {
      id: "findings.issue.split",
      title: "Split issue…",
      group: "Findings",
      keywords: "separate new issue",
      hidden: !active,
      disabled: noIssue || (openIssue && issueActionProblems(openIssue, issues.size).split) || false,
      run: () => openIssue && setIssueDialog({ kind: "split", issue: openIssue }),
    },
    {
      id: "findings.report",
      title: "Build a report…",
      group: "Findings",
      keywords: "export html pdf word docx markdown csv sarif defectdojo",
      run: () => {
        app.setTab("findings");
        setReporting(true);
      },
    },
  ]);

  // The open finding stays in view as the keyboard moves through the list.
  const tree = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (selected != null) tree.current?.querySelector(`[data-finding="${selected}"]`)?.scrollIntoView({ block: "nearest" });
  }, [selected, open]);

  const toggle = <T,>(set: Set<T>, v: T) => {
    const s = new Set(set);
    s.has(v) ? s.delete(v) : s.add(v);
    return s;
  };

  return (
    <div className="col fill">
      <div className="toolbar">
        <div className="seg" role="group" aria-label="Risks shown">
          {RISKS.map((r) => (
            <button key={r} className={risks.has(r) ? "on" : ""} aria-pressed={risks.has(r)} onClick={() => setRisks(toggle(risks, r))}>
              <span className={`dot-risk risk-${r}`} /> {r} <span className="muted">{counts[r] ?? 0}</span>
            </button>
          ))}
        </div>
        <input
          className="input"
          style={{ width: 200 }}
          placeholder="Search: name, URL, evidence, #id"
          value={filter.text}
          onChange={(e) => setFilter({ ...filter, text: e.target.value })}
          onKeyDown={(e) => e.key === "Escape" && setFilter({ ...filter, text: "" })}
        />
        <select className="input" value={filter.source} onChange={(e) => setFilter({ ...filter, source: e.target.value as Source })} title="Which scanner raised it">
          {SOURCES.map((s) => (
            <option key={s.id} value={s.id}>
              {s.label}
            </option>
          ))}
        </select>
        {hosts.length > 1 && (
          <select className="input" value={filter.host} onChange={(e) => setFilter({ ...filter, host: e.target.value })} title="The host it was found on">
            <option value="">Any host</option>
            {hosts.map((h) => (
              <option key={h} value={h}>
                {h}
              </option>
            ))}
          </select>
        )}
        <label className="check" title="False positives, accepted risks and fixed findings">
          <input type="checkbox" checked={hideFp} onChange={(e) => setHideFp(e.target.checked)} /> Hide closed
        </label>
        <select className="input" value={compare} onChange={(e) => setCompare(e.target.value as Compare)} title={COMPARE.find((c) => c.id === compare)!.title}>
          {COMPARE.map((c) => (
            <option key={c.id} value={c.id} disabled={c.id !== "all" && !scans.length} title={c.title}>
              {c.label}
              {c.id === "all" ? "" : " scan…"}
            </option>
          ))}
        </select>
        {compare !== "all" && (
          <select className="input" value={scan?.id ?? ""} onChange={(e) => setScanId(Number(e.target.value))} title="The scan to compare with">
            {scans.map((j) => (
              <option key={j.id} value={j.id}>
                #{j.id} {new Date(j.time).toLocaleString()} · {j.args.filter((a) => /^https?:\/\//i.test(a)).join(" ") || "recorded traffic"}
              </option>
            ))}
          </select>
        )}
        <div className="toolbar-end">
          <span className="muted">
            {groups.length} issue{groups.length === 1 ? "" : "s"} · {shown.length} finding{shown.length === 1 ? "" : "s"}
          </span>
          {heldNote(data) && (
            <span className="warn-text" role="status">
              {heldNote(data)}
            </span>
          )}
          <button className="btn small" onClick={() => app.newFinding({})} title="Write up an issue you found by hand (nothing is sent)">
            New finding…
          </button>
          <button className="btn small" onClick={() => setReporting(true)} title="Build a report: who it is for, its sections and branding, which findings; HTML, PDF, Word, Markdown, JSON, CSV, SARIF or DefectDojo">
            Report…
          </button>
        </div>
      </div>
      {picked.length > 0 && (
        <div className="toolbar bulk-bar">
          <strong>{picked.length} selected</strong>
          <span className="muted">Mark as</span>
          <div className="seg">
            {STATES.map((s) => (
              <button key={s.id} disabled={busy} title={s.title} onClick={() => markPicked(s.id)}>
                {s.label}
              </button>
            ))}
          </div>
          {pickedFor.merge.length > 0 && (
            <button
              className="btn small"
              disabled={busy}
              onClick={() => setIssueDialog({ kind: "merge", from: pickedFor.merge, targets: pickedFor.merge })}
              title="Keep one of the ticked findings' issues and move every finding of the others into it"
            >
              Merge their issues…
            </button>
          )}
          {pickedFor.split && (
            <button className="btn small" disabled={busy} onClick={() => pickedFor.split && setIssueDialog({ kind: "split", issue: pickedFor.split })} title="Move the ticked findings out of their issue into a new one">
              Split off…
            </button>
          )}
          {picked.length < shown.length && (
            <button className="btn small" disabled={busy} onClick={() => setChecked(new Set(shown))}>
              Select all {shown.length} shown
            </button>
          )}
          <button className="btn small" disabled={busy} onClick={() => setChecked(new Set())}>
            Clear selection
          </button>
        </div>
      )}
      <Split id="findings" dir="row" initial={0.34}>
        <div className="tree" ref={tree}>
          {groups.length === 0 && (
            <div className="empty">
              {comparing
                ? compare === "gone"
                  ? "Nothing that this scan covered is missing: no fixes to show yet."
                  : "No findings match this comparison."
                : filtering
                  ? "No findings match the search and filters."
                  : "No findings. Passive rules run on recorded traffic; active scans add more."}
            </div>
          )}
          {groups.map((g) => {
            const ids = g.items.map((f) => f.id);
            const n = ids.filter((id) => checked.has(id)).length;
            return (
              <div key={g.key}>
                <div className="tree-row">
                  <input
                    type="checkbox"
                    className="tree-check"
                    aria-label={`Select every ${g.name} finding on ${hostsOf(g.items).join(", ")}`}
                    checked={n === ids.length}
                    ref={(el) => {
                      if (el) el.indeterminate = n > 0 && n < ids.length;
                    }}
                    onChange={(e) => {
                      const next = new Set(checked);
                      for (const id of ids) e.target.checked ? next.add(id) : next.delete(id);
                      setChecked(next);
                    }}
                  />
                  <button
                    className="tree-group"
                    aria-expanded={open.has(g.key) || filter.text !== ""}
                    onClick={() => setOpen(toggle(open, g.key))}
                    onContextMenu={(e) => {
                      if (!g.issue) return;
                      e.preventDefault();
                      issueMenu.open(e, issueMenuItems(g.issue));
                    }}
                  >
                    <span className="caret">{open.has(g.key) ? "▾" : "▸"}</span>
                    <span className={`dot-risk risk-${g.risk}`} />
                    <span className="grow ellipsis" title={g.issue?.titled ? `Renamed; the alert is ${g.name}` : undefined}>
                      {g.title}
                      {hosts.length > 1 && <span className="muted"> · {hostsOf(g.items).join(", ")}</span>}
                    </span>
                    {isScriptAnswer(g.alert) && (
                      <span className="tag warn" title={SCRIPT_ANSWER_NOTE}>
                        script answer
                      </span>
                    )}
                    {g.alert.startsWith("manual:") &&
                      [...new Set(g.items.map((f) => addedBy(f.origin).tag))].map((t) => (
                        <span key={t} className="tag">
                          {t}
                        </span>
                      ))}
                    {g.issue?.cvss && (
                      <span className="tag" title={g.issue.cvss.vector}>
                        {cvssLabel(g.issue)}
                      </span>
                    )}
                    <span className="muted">{g.items.length}</span>
                  </button>
                </div>
                {/* A search opens every group it matches, so the matches are in view. */}
                {(open.has(g.key) || filter.text !== "") &&
                  g.items.map((f) => (
                    <div key={f.id} className="tree-row">
                      <input
                        type="checkbox"
                        className="tree-check item"
                        aria-label={`Select finding ${f.id}`}
                        checked={checked.has(f.id)}
                        onChange={() => setChecked(toggle(checked, f.id))}
                      />
                      <button
                        data-finding={f.id}
                        className={`tree-item ${selected === f.id ? "on" : ""} ${CLOSED.has(f.state) ? "struck" : ""}`}
                        aria-current={selected === f.id ? "true" : undefined}
                        onClick={() => setSelected(f.id)}
                      >
                        <span className="ellipsis">
                          {/* One rule can raise differently named alerts (e.g. 40018 for each database). */}
                          {f.name !== g.name && <span className="tree-subname">{f.name} · </span>}
                          {f.url}
                          {f.param && <span className="muted"> [{f.param}]</span>}
                        </span>
                        {noteDrafts.has(f.id) && (
                          <span className="tag warn" title="A note typed for this finding isn't saved yet">
                            unsaved note
                          </span>
                        )}
                        {f.state !== "open" && <span className="tag">{STATES.find((s) => s.id === f.state)?.label ?? f.state}</span>}
                      </button>
                    </div>
                  ))}
              </div>
            );
          })}
        </div>
        {finding ? (
          <Split id="finding-detail" dir="col" initial={0.5}>
            <div className="detail">
              <div className="detail-head">
                <RiskBadge risk={finding.risk} />
                <h2>{finding.name}</h2>
              </div>
              {isScriptAnswer(finding.alert_ref) && (
                <p className="warn-text" role="note">
                  {SCRIPT_ANSWER_NOTE}
                </p>
              )}
              <div className="toolbar flat">
                <div className="seg" role="group" aria-label="Triage state">
                  {STATES.map((s) => (
                    <button key={s.id} className={finding.state === s.id ? "on" : ""} aria-pressed={finding.state === s.id} title={s.title} onClick={() => mark(s.id)}>
                      {s.label}
                    </button>
                  ))}
                </div>
                {finding.source === "passive" && (
                  <button className="btn small" disabled={retesting} onClick={retest} title="Send the request again and record whether the finding is still there">
                    {retesting ? "Retesting…" : "Retest"}
                  </button>
                )}
                {entry && (
                  <button className="btn small" onClick={sendToReplay} title={finding.attack ? "Open the attack in Replay, its payload highlighted" : undefined}>
                    Send to Replay
                  </button>
                )}
                {canVerify(finding) && (
                  <button
                    className="btn small"
                    disabled={verifying}
                    onClick={verify}
                    title="Send the request the scan started from and the attack again, now, and compare the responses: does the payload make the difference?"
                  >
                    {verifying ? "Comparing…" : "Compare with/without payload"}
                  </button>
                )}
                {openIssue && (
                  <button
                    className="btn small"
                    aria-haspopup="menu"
                    onClick={(e) => issueMenu.open(e, issueMenuItems(openIssue))}
                    title="Rename this finding's issue, rate it with CVSS 4.0, merge it into another or split findings off it"
                  >
                    Issue ▾
                  </button>
                )}
                <button
                  className="btn small"
                  aria-haspopup="menu"
                  onClick={(e) =>
                    ticketMenu.open(e, [
                      { label: "Copy for GitHub", action: () => copyTicket("github"), hint: "Markdown: what, where, how to fix and reproduce it" },
                      { label: "Copy for Jira", action: () => copyTicket("jira"), hint: "The same, in a block Jira shows as it is" },
                      "-",
                      { label: "Record GitHub ticket…", action: () => recordTicket("github"), hint: "Keep the link of the issue you filed" },
                      { label: "Record Jira ticket…", action: () => recordTicket("jira"), hint: "Keep the link of the issue you filed" },
                    ])
                  }
                  title="Write this finding up as a GitHub or Jira issue (nothing is sent), or record the one you filed"
                >
                  Ticket ▾
                </button>
                <button className="btn small" onClick={saveRepro} title="Save a JSON repro pack: the request (secrets masked), a curl command, the response around the evidence and how to check it again">
                  Repro pack…
                </button>
                {finding.source === "manual" && finding.state !== "removed" && (
                  <button className="btn small" onClick={() => setEditing(finding)} title="Change this finding's title, risk, URL, evidence or write-up">
                    Edit…
                  </button>
                )}
                {finding.source === "manual" && (
                  <button className="btn small" onClick={remove} title="Take this finding out of the findings and reports">
                    Remove
                  </button>
                )}
              </div>
              <dl className="facts">
                {openIssue && (
                  <>
                    <dt>Issue</dt>
                    <dd>
                      #{openIssue.id} {openIssue.title}
                      {openIssue.instances > 1 && <span className="muted"> · {openIssue.instances} findings</span>}
                      {openIssue.cvss && (
                        <>
                          {" · "}
                          {cvssLabel(openIssue)} <span className="mono muted">{openIssue.cvss.vector}</span>
                        </>
                      )}
                    </dd>
                  </>
                )}
                <dt>URL</dt>
                <dd className="mono">
                  {finding.method} {finding.url}
                </dd>
                {finding.param && (
                  <>
                    <dt>Parameter</dt>
                    <dd className="mono">{finding.param}</dd>
                  </>
                )}
                {finding.attack && (
                  <>
                    <dt>Attack</dt>
                    <dd className="mono">{finding.attack}</dd>
                  </>
                )}
                {finding.evidence && (
                  <>
                    <dt>Evidence</dt>
                    <dd className="mono">{finding.evidence}</dd>
                  </>
                )}
                <dt>Confidence</dt>
                <dd>{finding.confidence}</dd>
                {finding.source === "manual" ? (
                  <>
                    <dt>Source</dt>
                    <dd>
                      {addedBy(finding.origin).text}
                      {finding.cwe ? ` · CWE-${finding.cwe}` : ""}
                      {finding.history_ids?.length ? ` · history ${finding.history_ids.map((h) => `#${h}`).join(", ")}` : ""}
                    </dd>
                  </>
                ) : (
                  <>
                    <dt>Rule</dt>
                    <dd>
                      {finding.alert_ref} ({finding.source}){finding.cwe ? ` · CWE-${finding.cwe}` : ""}
                      {finding.wasc ? ` · WASC-${finding.wasc}` : ""} · {finding.hits} hit{finding.hits === 1 ? "" : "s"}
                    </dd>
                  </>
                )}
              </dl>
              {verified && verified.id === finding.id && <VerifyStrip v={verified} onDiff={() => openVerifyDiff(app, verified).catch((e) => app.toast(e.message, "error"))} />}
              {trail && trailLine(trail) && <p className={trail.reviewed_by ? "muted" : "warn-text"}>{trailLine(trail)}</p>}
              {suggestions.map((s) => (
                <div key={s.id} className="suggestion" role="group" aria-label="Suggestion">
                  <p>
                    <strong>{s.by ? `Suggested ${s.by}` : "Suggested"}</strong>
                    <span className="muted"> · {new Date(s.time).toLocaleString()}</span>
                  </p>
                  <p>{suggestionText(s).replace(/^Suggested: /, "")}</p>
                  <div className="toolbar flat">
                    <button
                      className="btn small"
                      onClick={() => accept(s)}
                      title="Mark the finding as suggested, as your own decision; refused if its state changed since you read it"
                    >
                      Accept
                    </button>
                    <button className="btn small" onClick={() => dismiss(s)} title="Hide this suggestion; nothing changes on the finding">
                      Dismiss
                    </button>
                  </div>
                </div>
              ))}
              {finding.issue_id != null && (
                <>
                  <h3>Write-up</h3>
                  <textarea
                    className="input note-input"
                    rows={4}
                    placeholder="What this issue means for this site, for the report. An agent can draft it; it's printed once a person reviews it."
                    value={writeup}
                    disabled={narrativeIssue !== finding.issue_id}
                    onChange={(e) => setWriteup(e.target.value)}
                  />
                  <div className="toolbar flat">
                    <button className="btn small" disabled={narrativeIssue !== finding.issue_id || writeup.trim() === (narrative?.text ?? "")} onClick={() => saveWriteup(false)}>
                      {writeup.trim() === "" && narrative ? "Clear write-up" : "Save write-up"}
                    </button>
                    {narrative && !narrative.reviewed_at && writeup.trim() === narrative.text && (
                      <button className="btn small" onClick={() => saveWriteup(true)} title="You've read it and it's right: reports print it">
                        Mark reviewed
                      </button>
                    )}
                    {narrative && <span className="muted">{narrativeCredit(narrative)}</span>}
                  </div>
                </>
              )}
              <h3>Note</h3>
              <textarea
                className="input note-input"
                rows={3}
                placeholder="Your triage notes: why it's confirmed or a false positive, what to retest. Reports show it."
                value={noteDraft}
                onChange={(e) => setNoteDraft(e.target.value)}
              />
              <div className="toolbar flat">
                <button className="btn small" disabled={noteDraft.trim() === (finding.note ?? "")} onClick={saveNote}>
                  {noteDraft.trim() === "" && finding.note ? "Clear note" : "Save note"}
                </button>
                {finding.note && <span className="muted">Written {noteBy(finding.note_origin, finding.note_changed_at)}</span>}
              </div>
              {events.length > 0 && (
                <>
                  <h3>Timeline</h3>
                  <ol className="timeline">
                    {events.map((e) => (
                      <li key={e.id} className={e.kind === "suggested" ? "suggested" : undefined}>
                        <span className="muted">{new Date(e.time).toLocaleString()}</span> {eventText(e)}
                        {e.by && <span className="muted"> · {e.by}</span>}
                      </li>
                    ))}
                  </ol>
                </>
              )}
              {finding.description && (
                <>
                  <h3>Description</h3>
                  <p className="prose">{finding.description}</p>
                </>
              )}
              {finding.other_info && (
                <>
                  <h3>Details</h3>
                  <p className="prose">{finding.other_info}</p>
                </>
              )}
              {finding.solution && (
                <>
                  <h3>Solution</h3>
                  <p className="prose">{finding.solution}</p>
                </>
              )}
              {!!finding.refs?.length && (
                <>
                  <h3>References</h3>
                  <ul className="refs">
                    {finding.refs.map((r) => (
                        <li key={r} className="mono">
                          {r}
                        </li>
                      ))}
                  </ul>
                </>
              )}
            </div>
            <Split id="finding-msg" dir="row">
              <HttpView
                title={reqRanges.marked ? `Request · ${reqRanges.marked} marked` : "Request"}
                value={entry ? bodyText(entry.request) : ""}
                binary={isBinary(entry?.request)}
                placeholder="No recorded request"
                ranges={reqRanges.ranges}
              />
              <HttpView title="Response" value={entry ? rawResponse(entry) : ""} binary={isBinary(entry?.response?.body)} placeholder="" highlight={finding.evidence} />
            </Split>
          </Split>
        ) : (
          <div className="blank">Select a finding to see its details and evidence.</div>
        )}
      </Split>
      <Menu menu={ticketMenu.menu} close={ticketMenu.close} />
      <Menu menu={issueMenu.menu} close={issueMenu.close} />
      {issueDialog?.kind === "cvss" && (
        <CvssDialog
          issue={issueDialog.issue}
          onClose={() => setIssueDialog(null)}
          onSaved={(c) => {
            app.toast(c ? `Issue #${issueDialog.issue.id} rated CVSS 4.0 ${c.score.toFixed(1)} (${c.severity}).` : `Issue #${issueDialog.issue.id} has no CVSS rating now.`);
            issueChanged();
          }}
        />
      )}
      {issueDialog?.kind === "merge" && (
        <MergeDialog
          from={issueDialog.from}
          targets={issueDialog.targets}
          onClose={() => setIssueDialog(null)}
          onMerged={(into, moved) => {
            app.toast(`Moved ${moved} finding${moved === 1 ? "" : "s"} into issue #${into}.`);
            setChecked(new Set());
            issueChanged(into);
          }}
        />
      )}
      {issueDialog?.kind === "split" && (
        <SplitDialog
          issue={issueDialog.issue}
          checked={new Set(picked)}
          onClose={() => setIssueDialog(null)}
          onSplit={(issue, moved) => {
            app.toast(`Moved ${moved.length} finding${moved.length === 1 ? "" : "s"} to new issue #${issue}.`);
            setChecked(new Set());
            issueChanged(issue);
          }}
        />
      )}
      {reporting && <ReportBuilder name={reportName} onClose={() => setReporting(false)} />}
      {app.findingDraft && <NewFinding draft={app.findingDraft} onClose={() => app.newFinding(null)} onAdded={added} />}
      {editing && <NewFinding draft={null} edit={editing} onClose={() => setEditing(null)} onEdited={edited} />}
    </div>
  );
}

/** The suggestions dismissed in a project, as this window's storage has them. */
function readDismissed(key: string): Set<number> {
  try {
    return parseDismissed(localStorage.getItem(key));
  } catch {
    return new Set();
  }
}

/** Whether two values read from the CLI are the same, so an unchanged poll doesn't render again. */
function same(a: unknown, b: unknown): boolean {
  return a === b || JSON.stringify(a) === JSON.stringify(b);
}

/** Whether a finding can be sent with and without its payload: one with an attack, or a baseline. */
function canVerify(f: Finding): boolean {
  return f.history_id != null && (!!f.attack || f.base_history_id != null);
}
