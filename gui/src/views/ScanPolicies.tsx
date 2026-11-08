// Scans › Policies: saved scan policies, each a choice of which active rules run, at what
// strength and threshold. New scan picks one; `scan active --policy NAME` from the CLI.

import { useMemo, useState } from "react";
import { run, type Risk } from "../api";
import { useApp } from "../store";
import { confirm } from "../ui/Confirm";
import { DataTable, type Column } from "../ui/DataTable";
import { usePoll } from "../ui/usePoll";
import {
  DEFAULT_POLICY,
  effective,
  enabledCount,
  nameProblem,
  policyOf,
  saveCommand,
  setEnabled,
  setRule,
  STRENGTHS,
  THRESHOLD_TEXT,
  THRESHOLDS,
  type Policy,
  type PolicySummary,
} from "./scanPolicy";

interface ActiveRule {
  id: number;
  name: string;
  scope: string;
  max_risk: Risk;
}

const RISK_RANK: Record<Risk, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** The saved policies, polled while `enabled`. */
export function usePolicies(enabled = true) {
  return usePoll<{ policies: PolicySummary[] }>(() => run(["scan", "policy", "list"]), 15000, enabled);
}

export function ScanPolicies({ active }: { active: boolean }) {
  const app = useApp();
  const [saved, refresh] = usePolicies(active);
  const [rules] = usePoll<{ rules: ActiveRule[] }>(() => run(["scan", "rules", "--active"]), 300000, active);
  // The policy being edited, and the saved one it was loaded from ("" for a new one).
  const [loaded, setLoaded] = useState("");
  const [name, setName] = useState("");
  const [policy, setPolicy] = useState<Policy>(DEFAULT_POLICY);
  const [filter, setFilter] = useState("");
  const [busy, setBusy] = useState(false);

  const load = (n: string) => {
    const s = saved?.policies.find((p) => p.name === n);
    setLoaded(s ? n : "");
    setName(s ? n : "");
    setPolicy(s ? policyOf(s) : DEFAULT_POLICY);
  };
  const ids = (rules?.rules ?? []).map((r) => r.id);
  const problem = nameProblem(name);
  const replacing = !!saved?.policies.some((p) => p.name === name.trim());

  const save = async () => {
    if (problem) return;
    if (replacing && name.trim() !== loaded && !(await confirm("Replace this policy?", `A policy named "${name.trim()}" is saved already.`, "Replace", "Cancel"))) return;
    setBusy(true);
    try {
      const c = saveCommand(name, policy);
      await run(c.args, c.stdin);
      app.toast(`Saved the scan policy "${name.trim()}".`);
      setLoaded(name.trim());
      setName(name.trim());
      refresh();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
    setBusy(false);
  };

  const remove = async () => {
    if (!loaded || !(await confirm("Remove this policy?", `"${loaded}" is removed from this project. Scans that used it keep their results.`, "Remove", "Keep"))) return;
    try {
      await run(["scan", "policy", "remove", loaded]);
      app.toast(`Removed the scan policy "${loaded}".`);
      load("");
      refresh();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  const rows = useMemo(() => {
    const t = filter.toLowerCase();
    return (rules?.rules ?? []).filter((r) => !t || r.name.toLowerCase().includes(t) || String(r.id).includes(t));
  }, [rules, filter]);

  const columns: Column<ActiveRule>[] = [
    {
      key: "on",
      label: "On",
      width: 40,
      value: (r) => (effective(policy, r.id).enabled ? 1 : 0),
      render: (r) => <input type="checkbox" checked={effective(policy, r.id).enabled} onChange={(e) => setPolicy(setEnabled(policy, r.id, e.target.checked))} />,
    },
    { key: "id", label: "ID", width: 64, value: (r) => r.id, align: "right" },
    { key: "name", label: "Name", width: 320, value: (r) => r.name },
    {
      key: "strength",
      label: "Strength",
      width: 150,
      value: (r) => STRENGTHS.indexOf(effective(policy, r.id).strength),
      render: (r) => (
        <select className="input small" value={policy.rules[String(r.id)]?.strength ?? ""} onChange={(e) => setPolicy(setRule(policy, r.id, { strength: e.target.value }))}>
          <option value="">policy's ({policy.strength})</option>
          {STRENGTHS.map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
      ),
    },
    {
      key: "threshold",
      label: "Threshold",
      width: 150,
      value: (r) => THRESHOLDS.indexOf(effective(policy, r.id).threshold),
      render: (r) => (
        <select
          className="input small"
          value={policy.rules[String(r.id)]?.threshold ?? ""}
          title={`Raises ${THRESHOLD_TEXT[effective(policy, r.id).threshold]}`}
          onChange={(e) => setPolicy(setRule(policy, r.id, { threshold: e.target.value }))}
        >
          <option value="">policy's ({policy.threshold})</option>
          {THRESHOLDS.map((t) => (
            <option key={t}>{t}</option>
          ))}
        </select>
      ),
    },
    {
      key: "risk",
      label: "Max risk",
      width: 90,
      value: (r) => RISK_RANK[r.max_risk],
      render: (r) => (
        <span className="row gap">
          <span className={`dot-risk risk-${r.max_risk}`} />
          {r.max_risk}
        </span>
      ),
    },
    { key: "scope", label: "Scope", width: 70, value: (r) => r.scope },
    {
      key: "own",
      label: "",
      width: 70,
      value: (r) => (effective(policy, r.id).own ? 1 : 0),
      render: (r) =>
        effective(policy, r.id).own ? (
          <button className="link small" onClick={() => setPolicy(setRule(policy, r.id, { enabled: undefined, strength: undefined, threshold: undefined }))} title="Use the policy's settings for this rule">
            reset
          </button>
        ) : null,
    },
  ];

  return (
    <div className="col fill">
      <div className="toolbar">
        <select className="input" value={loaded} onChange={(e) => load(e.target.value)} title="Edit a saved policy, or start a new one">
          <option value="">New policy</option>
          {saved?.policies.map((p) => (
            <option key={p.name} value={p.name}>
              {p.name}
            </option>
          ))}
        </select>
        <input className="input" style={{ width: 180 }} placeholder="Policy name" value={name} onChange={(e) => setName(e.target.value)} />
        <button className="btn small primary" disabled={!!problem || busy} onClick={save} title={problem ?? "Keep this policy in the project, for New scan and scan active --policy"}>
          Save
        </button>
        {loaded && (
          <button className="btn small" onClick={remove}>
            Remove
          </button>
        )}
        <span className="sep" />
        <label className="row gap">
          <span className="muted">Strength</span>
          <select className="input" value={policy.strength} onChange={(e) => setPolicy({ ...policy, strength: e.target.value as Policy["strength"] })} title="How many attacks each rule tries, unless set apart below">
            {STRENGTHS.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </label>
        <label className="row gap">
          <span className="muted">Threshold</span>
          <select
            className="input"
            value={policy.threshold}
            onChange={(e) => setPolicy({ ...policy, threshold: e.target.value as Policy["threshold"] })}
            title="How sure a rule must be to raise a finding: low raises every finding, medium those of medium or high confidence, high only high-confidence ones. The attacks sent are the same."
          >
            {THRESHOLDS.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </label>
        <label className="check" title="Off: only the rules ticked below run, and rules added in a later version stay off">
          <input type="checkbox" checked={policy.enabled} onChange={(e) => setPolicy({ ...policy, enabled: e.target.checked })} /> Rules on unless turned off
        </label>
        <span className="grow" />
        <input className="input" style={{ width: 160 }} placeholder="Filter: name or id" value={filter} onChange={(e) => setFilter(e.target.value)} />
      </div>
      <p className="muted small sc-all">
        {enabledCount(policy, ids)} of {ids.length} rules on. Threshold {policy.threshold} raises {THRESHOLD_TEXT[policy.threshold]}; a finding below
        its rule's threshold isn't raised (the scan counts it). A scan's own strength, rules or threshold win over its policy.
      </p>
      <DataTable rows={rows} columns={columns} rowKey={(r) => r.id} initialSort={{ key: "id", desc: false }} empty={rules ? "No rules match." : "Loading rules…"} />
    </div>
  );
}
