/** Internal bounded JSON member scanner; callers own their error surface. */
export function assertUniqueJsonKeys(source: string): void {
  let position = 0;
  let nodes = 0;
  const whitespace = /[\u0009\u000a\u000d\u0020]/u;
  const skipWhitespace = (): void => {
    while (position < source.length && whitespace.test(source[position] ?? "")) position += 1;
  };
  const stringToken = (): string => {
    if (source[position] !== '"') throw new Error("expected JSON string");
    const start = position;
    position += 1;
    for (;;) {
      const character = source[position];
      if (character === undefined || character.charCodeAt(0) < 0x20) throw new Error("invalid JSON string");
      position += 1;
      if (character === '"') return JSON.parse(source.slice(start, position)) as string;
      if (character !== "\\") continue;
      const escape = source[position];
      if (escape === undefined || !'"\\/bfnrtu'.includes(escape)) throw new Error("invalid JSON escape");
      position += 1;
      if (escape === "u") {
        const scalar = source.slice(position, position + 4);
        if (!/^[0-9a-fA-F]{4}$/u.test(scalar)) throw new Error("invalid JSON Unicode escape");
        position += 4;
      }
    }
  };
  const value = (depth: number): void => {
    nodes += 1;
    if (depth > 64 || nodes > 100_000) throw new Error("JSON exceeds nesting or node bounds");
    skipWhitespace();
    const initial = source[position];
    if (initial === '"') {
      stringToken();
      return;
    }
    if (initial === "{") {
      position += 1;
      skipWhitespace();
      const keys = new Set<string>();
      if (source[position] === "}") {
        position += 1;
        return;
      }
      for (;;) {
        skipWhitespace();
        const key = stringToken();
        if (keys.has(key)) throw new Error("JSON object contains a duplicate key");
        keys.add(key);
        skipWhitespace();
        if (source[position] !== ":") throw new Error("JSON object lacks a colon");
        position += 1;
        value(depth + 1);
        skipWhitespace();
        if (source[position] === "}") {
          position += 1;
          return;
        }
        if (source[position] !== ",") throw new Error("JSON object lacks a separator");
        position += 1;
      }
    }
    if (initial === "[") {
      position += 1;
      skipWhitespace();
      if (source[position] === "]") {
        position += 1;
        return;
      }
      for (;;) {
        value(depth + 1);
        skipWhitespace();
        if (source[position] === "]") {
          position += 1;
          return;
        }
        if (source[position] !== ",") throw new Error("JSON array lacks a separator");
        position += 1;
      }
    }
    const start = position;
    while (position < source.length && !/[\u0009\u000a\u000d\u0020,\]}]/u.test(source[position] ?? "")) position += 1;
    if (position === start) throw new Error("JSON value is missing");
    JSON.parse(source.slice(start, position));
  };
  value(0);
  skipWhitespace();
  if (position !== source.length) throw new Error("JSON contains trailing data");
}

