// Replay state that outlives a tab's view. Switching tabs remounts the view, so a send or race
// still running when the user switches away must land in the tab's state, not in the unmounted
// view's. Each open project gets its own store (Replay makes one when it mounts): tab keys start
// at 1 again in the next project, so a shared store would hand its tabs the old ones' history and
// running sends. No DOM, so it can be tested on its own (replayState.test.ts).

export interface TabStore<S> {
  /** The tab's latest state, or the empty one. */
  get(key: number): S;
  /** Applies `f` to the tab's latest state, keeps the result, and passes it to the tab's view if one is showing. Dropped once the store stopped. */
  update(key: number, f: (s: S) => S): void;
  /** Registers the view showing the tab; returns the call that unregisters it. */
  listen(key: number, view: (s: S) => void): () => void;
  /** Takes updates until the returned call stops it (the project closed). */
  start(): () => void;
  /** Whether it takes updates: a send or race that ends after its project closed does nothing more. */
  live(): boolean;
}

export function tabStore<S>(empty: S): TabStore<S> {
  const states = new Map<number, S>();
  const views = new Map<number, (s: S) => void>();
  // Live from the start; StrictMode stops and starts it again once in development.
  let live = true;
  const get = (key: number) => (states.has(key) ? (states.get(key) as S) : empty);
  return {
    get,
    update(key, f) {
      if (!live) return;
      const next = f(get(key));
      states.set(key, next);
      views.get(key)?.(next);
    },
    listen(key, view) {
      views.set(key, view);
      return () => {
        if (views.get(key) === view) views.delete(key);
      };
    },
    start() {
      live = true;
      return () => {
        live = false;
      };
    },
    live: () => live,
  };
}
