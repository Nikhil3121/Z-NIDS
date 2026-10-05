import { useEffect, useState } from "react";

/** Debounce a value (search boxes) so typing does not fire a request per keystroke. */
export function useDebounced<T>(value: T, delay = 350): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = window.setTimeout(() => setV(value), delay);
    return () => window.clearTimeout(t);
  }, [value, delay]);
  return v;
}
