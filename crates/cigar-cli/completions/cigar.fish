complete -c cigar -f
complete -c cigar -n '__fish_use_subcommand' -a 'init source ingest status context project focus space handoff effect replay policy backup gc diagnostics doctor serve mcp plugin release completion man help version'
complete -c cigar -n '__fish_seen_subcommand_from source' -a 'add list refresh inspect remove'
complete -c cigar -n '__fish_seen_subcommand_from context' -a 'plan compile explain diff revalidate materialize'
complete -c cigar -n '__fish_seen_subcommand_from project' -a 'list attach detach switch link unlink'
complete -c cigar -n '__fish_seen_subcommand_from focus' -a 'new switch checkpoint close'
complete -c cigar -n '__fish_seen_subcommand_from space' -a 'fork publish log conflicts'
complete -c cigar -n '__fish_seen_subcommand_from handoff' -a 'create preview inspect accept revoke merge'
complete -c cigar -n '__fish_seen_subcommand_from effect' -a 'prepare approve dispatch list inspect reconcile compensate'
complete -c cigar -n '__fish_seen_subcommand_from replay' -a 'reconstruct run compare completeness'
complete -c cigar -n '__fish_seen_subcommand_from policy' -a 'check explain'
complete -c cigar -n '__fish_seen_subcommand_from backup' -a 'create verify restore'
complete -c cigar -n '__fish_seen_subcommand_from gc' -a 'plan run'
complete -c cigar -n '__fish_seen_subcommand_from diagnostics' -a 'bundle'
complete -c cigar -n '__fish_seen_subcommand_from mcp' -a 'serve'
complete -c cigar -n '__fish_seen_subcommand_from plugin' -a 'install uninstall doctor'
complete -c cigar -n '__fish_seen_subcommand_from release' -a 'verify'
complete -c cigar -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
complete -c cigar -l output -a 'text json'
complete -c cigar -l deadline -r
complete -c cigar -l config -r
complete -c cigar -l target -a 'embedded local remote'
complete -c cigar -l embedded
complete -c cigar -l local
complete -c cigar -l remote -r
complete -c cigar -l endpoint -r
complete -c cigar -l authorization-file -r
complete -c cigar -l input -r
complete -c cigar -l dry-run
complete -c cigar -l yes
complete -c cigar -l non-interactive
complete -c cigar -l quiet
complete -c cigar -l color -a 'auto always never'
complete -c cigar -l unicode -a 'auto always never'
complete -c cigar -l security
complete -c cigar -l deep
