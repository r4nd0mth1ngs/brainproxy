// Right-click menu, positioned at the cursor and closed by any outside click or Escape.

import { useEffect, useState } from "react";

export interface MenuItem {
  label: string;
  action: () => void;
  disabled?: boolean;
  /** Shown under the label, such as why the item is disabled. */
  hint?: string;
}

export type MenuState = { x: number; y: number; items: (MenuItem | "-")[] } | null;

export function useMenu() {
  const [menu, setMenu] = useState<MenuState>(null);
  const open = (e: { clientX: number; clientY: number }, items: (MenuItem | "-")[]) =>
    setMenu({ x: e.clientX, y: e.clientY, items });
  return { menu, open, close: () => setMenu(null) };
}

export function Menu({ menu, close }: { menu: MenuState; close: () => void }) {
  useEffect(() => {
    if (!menu) return;
    const key = (e: KeyboardEvent) => e.key === "Escape" && close();
    window.addEventListener("mousedown", close);
    window.addEventListener("keydown", key);
    window.addEventListener("blur", close);
    return () => {
      window.removeEventListener("mousedown", close);
      window.removeEventListener("keydown", key);
      window.removeEventListener("blur", close);
    };
  }, [menu, close]);
  if (!menu) return null;
  const x = Math.min(menu.x, window.innerWidth - 240);
  const hints = menu.items.filter((it) => it !== "-" && it.hint).length;
  const y = Math.min(menu.y, window.innerHeight - menu.items.length * 26 - hints * 16 - 12);
  return (
    <div className="menu" style={{ left: x, top: y }} onMouseDown={(e) => e.stopPropagation()}>
      {menu.items.map((it, i) =>
        it === "-" ? (
          <div key={i} className="menu-sep" />
        ) : (
          // aria-disabled rather than disabled, so a disabled item can still be focused and its
          // hint read out by a screen reader; clicking it does nothing.
          <button
            key={i}
            className="menu-item"
            aria-disabled={it.disabled || undefined}
            onClick={() => {
              if (it.disabled) return;
              close();
              it.action();
            }}
          >
            {it.label}
            {it.hint && <span className="menu-hint">{it.hint}</span>}
          </button>
        ),
      )}
    </div>
  );
}
