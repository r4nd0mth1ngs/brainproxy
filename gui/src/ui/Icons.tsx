// Small stroke icons for the sidebar (24x24 grid, currentColor).

const PATHS: Record<string, string> = {
  overview: "M4 4h7v7H4z M13 4h7v4h-7z M13 10h7v10h-7z M4 13h7v7H4z",
  sitemap: "M9 3h6v5H9z M3 16h6v5H3z M15 16h6v5h-6z M12 8v4 M6 16v-4h12v4",
  proxy: "M4 8h14l-3-3 M20 16H6l3 3",
  replay: "M4 12a8 8 0 1 0 2.5-5.8 M4 4v5h5",
  fuzzer: "M13 3 5 14h6l-1 7 8-11h-6z",
  scans: "M12 12l6-6 M21 12a9 9 0 1 1-9-9 M17 12a5 5 0 1 1-5-5",
  findings: "M12 3 5 6v6c0 4.5 3 7.5 7 9 4-1.5 7-4.5 7-9V6z M12 9v4 M12 16.5v.01",
  callbacks: "M12 21v-8 M8.5 9.5a5 5 0 0 1 7 0 M5.5 6.5a9 9 0 0 1 13 0 M12 13v.01",
  codec: "M8 7l-5 5 5 5 M16 7l5 5-5 5 M14 4l-4 16",
  diff: "M8 4H5v16h3 M16 4h3v16h-3 M10 9h4 M12 7v4 M10 16h4",
  settings:
    "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z M12 2v3 M12 19v3 M4.9 4.9 7 7 M17 17l2.1 2.1 M2 12h3 M19 12h3 M4.9 19.1 7 17 M17 7l2.1-2.1",
  collapse: "M15 6l-6 6 6 6",
  expand: "M9 6l6 6-6 6",
  theme: "M12 3a9 9 0 1 0 9 9 7 7 0 0 1-9-9z",
  switch: "M4 7h13l-3-3 M20 17H7l3 3",
  save: "M5 3h11l3 3v15H5z M8 3v5h7V3 M8 21v-7h8v7",
  arrow: "M5 12h14 M13 6l6 6-6 6",
  globe: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M3 12h18 M12 3c2.5 2.7 3.5 5.7 3.5 9s-1 6.3-3.5 9c-2.5-2.7-3.5-5.7-3.5-9s1-6.3 3.5-9z",
};

export function Icon({ name, size = 16 }: { name: keyof typeof PATHS | string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden className="icon">
      <path d={PATHS[name] ?? ""} />
    </svg>
  );
}
