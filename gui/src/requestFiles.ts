// Where the dev bridge (vite.config.ts) puts the private request files of one CLI call, as the
// Tauri shell's `race_files.rs` does: the extra requests of a race (`--also=@request:I`) and
// macro steps given as text (`--step=@request:I`, `--step=ORIGIN=@request:I`). Only these
// arguments, so a staged file can't be put into any other.

/** The index in `args` of the placeholder for request file `i`, or -1 when there is none. */
export function requestFileArg(args: string[], i: number): number {
  const marker = `@request:${i}`;
  return args.findIndex((a) => a === `--also=${marker}` || (a.startsWith("--step=") && a.endsWith(`=${marker}`)));
}

/** The placeholder `arg` for request file `i` with the file's `path` in its place. */
export function withRequestFile(arg: string, i: number, path: string): string {
  return arg.slice(0, -`@request:${i}`.length) + path;
}
