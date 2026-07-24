# Bash completion for meraki2tf — static flag-name completion.
#
# Hand-maintained against src/meraki2tf/cli.py (build_parser); update
# this list when flags change. Install:
#
#   source deploy/completion/meraki2tf.bash            # current shell
#   # or system-wide:
#   cp deploy/completion/meraki2tf.bash /etc/bash_completion.d/meraki2tf
#
# Deliberately simple: completes flag names when the current word
# starts with '-', and falls back to ordinary filename completion
# otherwise (most value-taking flags take paths).

_meraki2tf_complete() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local flags="
        --help
        --version
        --list-orgs
        --check
        --estimate
        --config
        --org-id
        --spec
        --workdir
        --terraform-bin
        --verbose
        --log-format
        --from-dump
        --dump-to
        --sanitize
        --drift-baseline
        --discovery-checkpoint
        --diff-networks
        --diff-out
        --sync
        --rebaseline
        --confirm-deletions
        --fail-on-gaps
        --rebuild
        --heal
        --only
        --replay-gaps
        --restore
        --wipe-org
        --confirm
        --expect-org
        --target-org
        --serial-map
        --skip-claims
        --wipe-org-name
        --state-file
        --state-backend
        --backend-config
        --backend-config-file
        --webhook-url
        --webhook-format
        --pagerduty
        --alert-email
        --smtp-host
        --smtp-port
        --email-from
    "
    if [[ "${cur}" == -* ]]; then
        COMPREPLY=( $(compgen -W "${flags}" -- "${cur}") )
    else
        COMPREPLY=( $(compgen -f -- "${cur}") )
    fi
}

complete -o filenames -F _meraki2tf_complete meraki2tf
