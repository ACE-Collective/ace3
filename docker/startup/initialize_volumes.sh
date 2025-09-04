#!/usr/bin/env bash
#

#
# when docker creates a named volume it creates it owned root:root
# this ensures that the volumes are owned by ace instead
#

for path in /opt/ace/data /opt/ace/ssl /docker-entrypoint-initdb.d /auth /home/ace
do
    #ls -ld ${path}
    if [[ $(stat -c "$U" ${path}) != "ace" ]]
    then
        chown ace:ace ${path}
    fi
done