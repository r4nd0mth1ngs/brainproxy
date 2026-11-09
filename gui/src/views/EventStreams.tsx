// Proxy → Event streams: the server-sent event streams (text/event-stream responses) the proxy
// relayed or Replay read, and their events, which keep arriving while a stream is open.

import { useEffect, useRef, useState } from "react";
import { bodyText, historyRequest, hostOf, pathOf, requireWhole, run } from "../api";
import { originOf, useApp } from "../store";
import { DataTable, type Column } from "../ui/DataTable";
import { HttpView } from "../ui/HttpView";
import { Menu, useMenu } from "../ui/Menu";
import { Split } from "../ui/Split";
import { usePoll } from "../ui/usePoll";
import { appendEvents, MAX_STREAM_BYTES, streamNote, type SseEvent, type SseStream } from "./sse";

const PREVIEW = 300;

const preview = (e: SseEvent) => {
  if (e.data == null) return "(no data)";
  const t = bodyText(e.data);
  return t.length > PREVIEW ? t.slice(0, PREVIEW) + "…" : t;
};

const STREAM_COLUMNS: Column<SseStream>[] = [
  { key: "id", label: "#", width: 50, value: (r) => r.id, align: "right" },
  { key: "host", label: "Host", width: 170, value: (r) => hostOf(r.url) },
  { key: "path", label: "URL", width: 300, value: (r) => pathOf(r.url) },
  { key: "state", label: "State", width: 70, value: (r) => r.state, render: (r) => <span className={r.state === "open" ? "s2" : "muted"}>{r.state}</span> },
  { key: "events", label: "Events", width: 80, value: (r) => r.events, align: "right" },
  { key: "source", label: "Source", width: 70, value: (r) => r.source },
  { key: "time", label: "Opened", width: 170, value: (r) => r.time },
  { key: "note", label: "Note", width: 260, value: (r) => streamNote(r), render: (r) => <span className={r.truncated ? "s4" : undefined}>{streamNote(r)}</span> },
];

const EVENT_COLUMNS: Column<SseEvent>[] = [
  { key: "id", label: "#", width: 56, value: (r) => r.id, align: "right" },
  { key: "event", label: "Event", width: 110, value: (r) => r.event },
  { key: "event_id", label: "Id", width: 80, value: (r) => r.event_id },
  { key: "length", label: "Length", width: 70, value: (r) => r.length ?? null, align: "right" },
  { key: "data", label: "Data", width: 460, value: (r) => preview(r) },
  { key: "retry", label: "Retry (ms)", width: 80, value: (r) => r.retry, align: "right" },
  { key: "time", label: "Time", width: 170, value: (r) => r.time },
];

/** One event with its whole data: no event is longer than what a stream may store. */
async function wholeEvent(id: number): Promise<SseEvent> {
  const e = await run<SseEvent>(["sse", "event", String(id), "--max-body", String(MAX_STREAM_BYTES)]);
  if (e.data) requireWhole(e.data, `Event #${id}`);
  return e;
}

export function EventStreams({ active }: { active: boolean }) {
  const app = useApp();
  const [streams] = usePoll<{ items: SseStream[] }>(() => run(["sse", "list", "--newest", "--limit", "5000"]), 2000, active);
  const [selected, setSelected] = useState<number | null>(null);
  const [events, setEvents] = useState<SseEvent[]>([]);
  const [current, setCurrent] = useState<number | null>(null);
  const [full, setFull] = useState<SseEvent | null>(null);
  const lastId = useRef(0);
  // The selection a poll's answer is for may have changed while it was on its way.
  const selectedRef = useRef<number | null>(null);
  selectedRef.current = selected;
  const { menu, open, close } = useMenu();
  const stream = streams?.items.find((s) => s.id === selected) ?? null;

  useEffect(() => {
    setEvents([]);
    setCurrent(null);
    lastId.current = 0;
  }, [selected]);

  // New events of the selected stream (ids only grow): an open stream fills in as it is relayed.
  usePoll(
    async () => {
      const id = selectedRef.current;
      if (id == null) return;
      const d = await run<{ items: SseEvent[] }>(["sse", "events", String(id), "--after", String(lastId.current), "--limit", "2000", "--max-body", String(PREVIEW + 1)]);
      if (id !== selectedRef.current || !d.items.length) return;
      lastId.current = d.items[d.items.length - 1].id!;
      setEvents((shown) => appendEvents(shown, d.items));
    },
    1000,
    active && selected != null,
  );

  useEffect(() => {
    if (current == null) return setFull(null);
    let live = true;
    wholeEvent(current)
      .then((e) => live && setFull(e))
      .catch((e) => live && app.toast(e.message, "error"));
    return () => {
      live = false;
    };
  }, [current, app.toast]);

  const streamMenu = (s: SseStream, ev: React.MouseEvent) =>
    open(ev, [
      {
        label: "Send to Replay",
        action: () => {
          if (s.history_id == null) return app.toast(`Stream #${s.id} has no recorded request`, "error");
          historyRequest(s.history_id)
            .then((h) => app.sendToRepeater({ raw: h.raw, binary: h.binary, target: originOf(s.url), title: `SSE ${pathOf(s.url).slice(0, 20)}` }))
            .catch((e) => app.toast(e.message, "error"));
        },
      },
      { label: "Copy URL", action: () => navigator.clipboard.writeText(s.url) },
    ]);

  const eventMenu = (e: SseEvent, ev: React.MouseEvent) =>
    open(ev, [
      {
        label: "Copy data",
        action: () =>
          e.id != null &&
          wholeEvent(e.id)
            .then((x) => navigator.clipboard.writeText(bodyText(x.data)))
            .catch((err) => app.toast(err.message, "error")),
      },
    ]);

  const items = streams?.items ?? [];
  return (
    <div className="col fill">
      <div className="toolbar">
        <span className="muted">
          {items.length} stream{items.length === 1 ? "" : "s"}
          {stream ? ` · #${stream.id} ${stream.url}${stream.history_id != null ? ` · history #${stream.history_id}` : ""}` : ""}
        </span>
        <span className="grow" />
        {stream?.truncated && (
          <span className="s4" title={stream.error ?? undefined}>
            Truncated: this stream went over what one may store, so later events are missing.
          </span>
        )}
      </div>
      <Split id="sse" dir="col" initial={0.3}>
        <DataTable
          rows={items}
          columns={STREAM_COLUMNS}
          rowKey={(r) => r.id}
          selected={selected}
          onSelect={(r) => setSelected(r.id)}
          onContextMenu={streamMenu}
          initialSort={{ key: "id", desc: true }}
          empty="No event streams yet. They appear here when a client using the proxy opens one (an EventSource, a streamed API answer)."
        />
        <Split id="sse-event" dir="row" initial={0.6}>
          <DataTable
            rows={events}
            columns={EVENT_COLUMNS}
            rowKey={(r) => r.id!}
            selected={current}
            onSelect={(r) => setCurrent(r.id)}
            onContextMenu={eventMenu}
            initialSort={{ key: "id", desc: false }}
            empty={selected == null ? "Select a stream" : stream?.state === "open" ? "No events yet" : "No events"}
          />
          <HttpView
            title={full ? `${full.event} #${full.id}${full.event_id != null ? ` · id ${full.event_id}` : ""}${full.retry != null ? ` · retry ${full.retry} ms` : ""}` : "Event"}
            value={full ? (full.data == null ? "" : bodyText(full.data)) : ""}
            placeholder={full && full.data == null ? "No data: a browser dispatches no event for this block" : "Select an event"}
          />
        </Split>
      </Split>
      <Menu menu={menu} close={close} />
    </div>
  );
}
