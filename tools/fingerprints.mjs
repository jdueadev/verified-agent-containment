// Groups differential mismatches by fingerprint: the event kind, the mode it
// arrived in and which fields differ. One defect leaves the same fingerprint on
// every transition it touches, so a report lists defects, not transitions.
import { writeFileSync } from "node:fs";

export const fields = (expected, got) =>
  Object.keys(expected).filter((k) => JSON.stringify(expected[k]) !== JSON.stringify(got[k]));

// With firstCases, the first whole case of each fingerprint is written there,
// one JSONL line each, so the inner loop can rerun it on its own.
export const groups = (firstCases) => {
  const seen = new Map();
  let current = null;
  return {
    case(line) { current = line; },
    add(event, fromMode, differing, example) {
      const key = `${event.type} in ${fromMode}: ${differing.join(",")}`;
      const group = seen.get(key) ?? { fingerprint: key, count: 0, first: example, line: current };
      group.count += 1;
      seen.set(key, group);
    },
    // Prints the summary on stdout and every group on stderr; exits 1 if any.
    finish(summary) {
      const list = [...seen.values()].sort((a, b) => b.count - a.count);
      const mismatches = list.reduce((n, g) => n + g.count, 0);
      for (const { line, ...g } of list) console.error(JSON.stringify(g));
      if (firstCases) writeFileSync(firstCases, list.map((g) => `${g.line}\n`).join(""));
      console.log(JSON.stringify({ ...summary, mismatches, fingerprints: list.map(({ fingerprint, count }) => ({ fingerprint, count })) }));
      process.exit(mismatches ? 1 : 0);
    },
  };
};
