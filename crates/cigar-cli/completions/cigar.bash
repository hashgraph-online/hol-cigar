_cigar_complete() {
    local current="${COMP_WORDS[COMP_CWORD]}"
    local previous="${COMP_WORDS[COMP_CWORD-1]}"
    local globals="--output --deadline --config --target --embedded --local --remote --endpoint --authorization-file --input --idempotency-key --expected-revision --page-cursor --page-size --dry-run --yes --confirm --non-interactive --quiet --color --unicode --width --explain-config --security --deep --force-full --help -h --version -V"
    local words=""
    case "${COMP_WORDS[1]}" in
        source) words="add list refresh inspect remove" ;;
        catalog) words="query" ;;
        context) words="plan compile explain diff revalidate materialize" ;;
        project) words="list attach detach switch link unlink" ;;
        focus) words="new switch checkpoint close" ;;
        space) words="fork publish log conflicts" ;;
        handoff) words="create preview inspect accept revoke merge" ;;
        effect) words="prepare approve dispatch list inspect reconcile compensate" ;;
        replay) words="reconstruct run compare completeness" ;;
        policy) words="check explain" ;;
        backup) words="create verify restore" ;;
        migration) words="preflight run activate cleanup" ;;
        compaction) words="preview execute status" ;;
        integrity) words="deep" ;;
        gc) words="plan run" ;;
        diagnostics) words="bundle" ;;
        state) words="inspect-beta import-beta restore-beta" ;;
        mcp) words="serve" ;;
        plugin) words="install uninstall doctor" ;;
        release) words="verify" ;;
        completion) words="bash zsh fish" ;;
        *) words="init source ingest catalog status context project focus space handoff effect replay policy backup migration compaction integrity gc diagnostics state doctor serve mcp plugin release completion man help version" ;;
    esac
    case "$previous" in
        --output) words="text json" ;;
        --target) words="embedded local remote" ;;
        --color|--unicode) words="auto always never" ;;
    esac
    COMPREPLY=( $(compgen -W "$words $globals" -- "$current") )
}
complete -F _cigar_complete cigar
