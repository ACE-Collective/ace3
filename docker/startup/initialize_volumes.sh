#!/usr/bin/env bash
#

#
# special handling for the phishkit volume
#

if [ ! -d /phishkit/input ]
then
    mkdir -p /phishkit/input
    chown ace:ace /phishkit/input
fi

if [ ! -d /phishkit/output ]
then
    mkdir -p /phishkit/output
    chown ace:ace /phishkit/output
fi

#
# when docker creates a named volume it creates it owned root:root
# this ensures that the volumes are owned by ace instead
#

for path in /opt/ace/data /opt/ace/data/external /opt/ace/ssl /docker-entrypoint-initdb.d /ace-sql-readonly /auth /home/ace /phishkit /phishkit/input /phishkit/output
do
    if [ -d "${path}" ]
    then
        if [[ $(stat -c "%U" ${path}) != "ace" ]]
        then
            chown ace:ace ${path}
        fi
    fi
done
