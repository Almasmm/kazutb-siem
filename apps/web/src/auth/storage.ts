class MemoryStorage implements Storage {
  private readonly values = new Map<string, string>();

  get length(): number {
    return this.values.size;
  }

  clear(): void {
    this.values.clear();
  }

  getItem(key: string): string | null {
    return this.values.get(key) ?? null;
  }

  key(index: number): string | null {
    return [...this.values.keys()][index] ?? null;
  }

  removeItem(key: string): void {
    this.values.delete(key);
  }

  setItem(key: string, value: string): void {
    this.values.set(key, String(value));
  }
}

class ResilientStorage implements Storage {
  private readonly fallback = new MemoryStorage();

  constructor(private readonly primary?: Storage) {}

  get length(): number {
    return this.keys().length;
  }

  clear(): void {
    this.fallback.clear();
    try { this.primary?.clear(); } catch { /* Continue with the in-memory session. */ }
  }

  getItem(key: string): string | null {
    try {
      const value = this.primary?.getItem(key) ?? null;
      if (value !== null) this.fallback.setItem(key, value);
      return value ?? this.fallback.getItem(key);
    } catch {
      return this.fallback.getItem(key);
    }
  }

  key(index: number): string | null {
    return this.keys()[index] ?? null;
  }

  removeItem(key: string): void {
    this.fallback.removeItem(key);
    try { this.primary?.removeItem(key); } catch { /* Continue with the in-memory session. */ }
  }

  setItem(key: string, value: string): void {
    this.fallback.setItem(key, value);
    try { this.primary?.setItem(key, value); } catch { /* Continue with the in-memory session. */ }
  }

  private keys(): string[] {
    const keys = new Set<string>();
    try {
      if (this.primary) {
        for (let index = 0; index < this.primary.length; index += 1) {
          const key = this.primary.key(index);
          if (key) keys.add(key);
        }
      }
    } catch {
      // The fallback below remains available when browser storage becomes unavailable.
    }
    for (let index = 0; index < this.fallback.length; index += 1) {
      const key = this.fallback.key(index);
      if (key) keys.add(key);
    }
    return [...keys];
  }
}

export function createSafeSessionStorage(resolve: () => Storage = () => window.sessionStorage): Storage {
  let primary: Storage | undefined;
  try {
    const candidate = resolve();
    const probe = "__kcsp_session_storage_probe__";
    const previous = candidate.getItem(probe);
    candidate.setItem(probe, "1");
    if (previous === null) candidate.removeItem(probe);
    else candidate.setItem(probe, previous);
    primary = candidate;
  } catch {
    primary = undefined;
  }
  return new ResilientStorage(primary);
}

export const authSessionStorage = createSafeSessionStorage();
