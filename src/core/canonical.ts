// The canonical form of an entry (SPEC §2): RFC 8785 (JCS) with numbers restricted to integers, which removes the
// one hard part of that RFC. A rule for writers: the chain itself is checked from a line's bytes, never from this.

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/** The canonical text of a value. Throws on anything the format doesn't allow (a fraction, an unsafe integer, undefined). */
export function canonical(value: Json): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error(`not an integer the format allows: ${value}`);
    return String(value === 0 ? 0 : value); // (never "-0")
  }
  // (ECMAScript's own string escaping is the one RFC 8785 asks for)
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (typeof value === 'object') {
    // (sorted by UTF-16 code units, as RFC 8785 §3.2.3: the default order of strings)
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => {
      const v = value[k];
      if (v === undefined) throw new Error(`member ${k} has no value`);
      return `${JSON.stringify(k)}:${canonical(v)}`;
    }).join(',')}}`;
  }
  throw new Error(`not a JSON value: ${typeof value}`);
}

/** A line parsed as a JSON object; null when it isn't one. */
export function parseLine(line: string): { [key: string]: Json } | null {
  try {
    const v: unknown = JSON.parse(line);
    return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as { [key: string]: Json }) : null;
  } catch { return null; }
}

/** Whether a line is exactly the canonical form of what it says. */
export function isCanonical(line: string): boolean {
  const v = parseLine(line);
  if (!v) return false;
  try { return canonical(v) === line; } catch { return false; }
}
