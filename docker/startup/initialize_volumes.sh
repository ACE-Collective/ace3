#!/usr/bin/env bash
#

#
# when docker creates a named volume it creates it owned root:root
# this ensures that the volumes are owned by ace instead
#

for path in /opt/ace/data /opt/ace/data/external /opt/ace/ssl /docker-entrypoint-initdb.d /ace-sql-readonly /auth /home/ace
do
    if [ -d "${path}" ]
    then
        if [[ $(stat -c "%U" ${path}) != "ace" ]]
        then
            chown ace:ace ${path}
        fi
    fi
done