// Groups differential mismatches by fingerprint: the event kind, the mode it
// arrived in and which fields differ. One defect leaves the same fingerprint on
// every transition it touches, so a report lists defects, not transitions.
export const fields = (expected, got) =>
  Object.keys(expected).filter((k) => JSON.stringify(expected[k]) !== JSON.stringify(got[k]));

export const groups = () => {
  const seen = new Map();
  return {
    add(event, fromMode, differing, example) {
      const key = `${event.type} in ${fromMode}: ${differing.join(",")}`;
      const group = seen.get(key) ?? { fingerprint: key, count: 0, first: example };
      group.count += 1;
      seen.set(key, group);
    },
    // Prints the summary on stdout and every group on stderr; exits 1 if any.
    finish(summary) {
      const list = [...seen.values()].sort((a, b) => b.count - a.count);
      const mismatches = list.reduce((n, g) => n + g.count, 0);
      for (const g of list) console.error(JSON.stringify(g));
      console.log(JSON.stringify({ ...summary, mismatches, fingerprints: list.map(({ fingerprint, count }) => ({ fingerprint, count })) }));
      process.exit(mismatches ? 1 : 0);
    },
  };
};
