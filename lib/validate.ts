export function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

export function isEmail(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  // simple RFC5322-lite
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

export function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === 'string');
}

export function requireFields<T extends Record<string, unknown>>(
  obj: T,
  fields: Array<keyof T>
): string[] {
  const missing: string[] = [];
  for (const f of fields) {
    const v = obj[f];
    if (v === undefined || v === null || (typeof v === 'string' && v.trim().length === 0)) {
      missing.push(String(f));
    }
  }
  return missing;
}


