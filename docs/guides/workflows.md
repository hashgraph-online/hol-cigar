# Project, source policy, and focus workflows

`cigar init` creates only project-owned local state. Sources are explicit: add, inspect, refresh, and
remove them through the source commands, and keep production source registries under daemon operator
control. Ignore rules, classification, symlink policy, file size, and generated/private path policy
are enforced before content is admitted.

Projects can be attached without merging their policy or authority. `project switch` changes the
active local reference; `project link` records an explicit relation. A focus creates a context space
for one task. Checkpoint before a handoff, close only when retained references are safe, and never use
focus state to bypass the current production policy.

For multi-project work:

1. Attach each project and inspect its source status.
2. Select the active project explicitly.
3. Create a named focus with bounded contract input.
4. Compile and inspect the selection manifest.
5. Checkpoint before handoff or effects.
6. Merge only after conflict and policy reauthorization.
