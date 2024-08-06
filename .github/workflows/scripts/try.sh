#!/bin/bash

# Usage: try [--max [30] --delay [2] --waitmsg 'retrying' --failmsg 'retrying' ] command...

try() {
    local max=30
    local delay=2
    local waitmsg="retrying"
    local failmsg=""
    while [[ $# -gt 0 ]] && [[ $1 == -* ]]; do
        case "$1" in
        --max)
            max=$2
            shift
            ;;
        --delay)
            delay=$2
            shift
            ;;
        --waitmsg)
            waitmsg=$2
            shift
            ;;
        --failmsg)
            failmsg=$2
            shift
            ;;
        --)
            shift
            break
            ;;
        *)
            printf "Usage error: unknown flag '%s'" "$1" >&2
            return 1
            ;;
        esac
        shift
    done

    local count=0
    while true; do
	$*
        status=$?
        count=$(expr $count + 1)
        if [[ $status -eq 0 ]]; then
          break
        elif [[ $count -ge $max ]]; then
            if [ -n "$failmsg" ] ; then
              echo $failmsg
            else
              echo "Failed to run <$*>"
            fi
            exit 1
            break
        fi
        echo "$waitmsg on try $count/$max"
        sleep $delay
    done
}
