// Per-browser conveniences only (e.g. last selected organization). Never auth tokens.
export function readPref(key: string): string | null {
  try {
    return window.localStorage.getItem(`sx:${key}`)
  } catch {
    return null
  }
}

export function writePref(key: string, value: string | null): void {
  try {
    if (value === null) window.localStorage.removeItem(`sx:${key}`)
    else window.localStorage.setItem(`sx:${key}`, value)
  } catch {
    /* storage unavailable (private mode) — preference is simply not remembered */
  }
}
