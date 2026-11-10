import { run, type CliInput } from "../api";
import { useApp } from "../store";

/** Runs a command, toasting its error; returns its data or undefined on failure. */
export function useRunner() {
  const app = useApp();
  return async <T,>(args: string[], input?: string | Uint8Array | CliInput): Promise<T | undefined> => {
    try {
      return await run<T>(args, input);
    } catch (e: any) {
      app.toast(e.message, "error");
      return undefined;
    }
  };
}
