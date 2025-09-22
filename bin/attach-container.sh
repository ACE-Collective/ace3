#!/usr/bin/env bash

USER="ace"
while getopts "u:" opt
do
    case ${opt} in
        u)
            USER="$OPTARG"
            ;;
        *)
            echo "invalid command line option ${opt}"
            exit 1
            ;;
    esac
done
shift $((OPTIND-1))

# attach to the dev container by default
TARGET_CONTAINER=$(bin/get-dev-container.sh)

# if the dev container does not exist, attach to the main ace container instead
if [ -z "$TARGET_CONTAINER" ]; then
    echo "attaching to ace container"
    TARGET_CONTAINER=$(bin/get-ace-container.sh)
else
    echo "attaching to dev container"
fi

docker exec -it -u $USER $TARGET_CONTAINER /bin/bash -il
