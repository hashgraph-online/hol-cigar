/**
 * Read-only observer for the Honey two-agent handoff workflow.
 *
 * The observer intentionally calls only disclosure-safe read operations. Its bearer token must
 * belong to a separately configured observer principal; the example never accepts, records,
 * merges, revokes, or otherwise acquires handoff authority.
 */

import { CigarClient } from "../index.js";

function required(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) throw new Error(`${name} is required`);
  return value;
}

function resultEventCount(commits: readonly unknown[]): number {
  let count = 0;
  for (const commit of commits) {
    if (typeof commit !== "object" || commit === null || Array.isArray(commit)) continue;
    const events = (commit as Record<string, unknown>).events;
    if (!Array.isArray(events)) continue;
    for (const event of events) {
      if (typeof event !== "object" || event === null || Array.isArray(event)) continue;
      const kind = (event as Record<string, unknown>).kind;
      if (kind === "agent_result_proposed" || kind === "merge_conflict_created") count += 1;
    }
  }
  return count;
}

const baseUrl = required("CIGAR_URL");
const client = new CigarClient({
  baseUrl,
  allowInsecureLoopback: baseUrl.startsWith("http://"),
  bearerToken: required("CIGAR_OBSERVER_TOKEN"),
});

await client.negotiate({ timeoutMs: 5_000 });
const preview = await client.previewHandoff({
  payload: { handoff_id: required("CIGAR_HANDOFF_ID") },
});
const spaceLog = await client.getSpaceLog({
  payload: { space_id: required("CIGAR_SPACE_ID") },
  pageSize: 100,
});

// Do not print task text, source material, result claims, credentials, or event payload digests.
console.log(JSON.stringify({
  handoff_id: preview.payload.handoff_id,
  accepted_capability_count: preview.payload.accepted_capabilities.length,
  rejected_capability_count: preview.payload.rejected_capabilities.length,
  accepted_project_count: preview.payload.accepted_projects.length,
  rejected_project_count: preview.payload.rejected_projects.length,
  reference_count: preview.payload.reference_count,
  visible_commit_count: spaceLog.payload.commits.length,
  visible_result_event_count: resultEventCount(spaceLog.payload.commits),
  more_commits_available: spaceLog.nextPageCursor !== undefined,
}, null, 2));
