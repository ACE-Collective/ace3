#!/usr/bin/env bash
#
# ensures all the files and directories that are needed exist
# and waits for the database connection to become available
# this file is sourced from every other startup file
#

cd /opt/ace
source /venv/bin/activate
source load_environment

# do we need to create fake ssl certificates?
if [ ! -f ssl/ace.cert.pem ]
then
    echo "installing self-signed SSL certificates"
    mkdir -p ssl
    openssl req \
        -x509 \
        -newkey rsa:4096 \
        -keyout ssl/ace.key.pem \
        -out ssl/ace.cert.pem \
        -sha256 \
        -days 3650 \
        -nodes \
        -subj "/C=US/ST=Ohio/L=Springfield/O=CompanyName/OU=CompanySectionName/CN=ace.local"

    cp ssl/ace.cert.pem ssl/ca-chain-combined.cert.pem
    cp ssl/ace.cert.pem ssl/ca-chain.cert.pem

    cp ssl/ace.key.pem ssl/mysql.key.pem
    cp ssl/ace.cert.pem ssl/mysql.cert.pem

    # Set proper permissions for SSL files
    chmod 600 ssl/ace.key.pem
    chmod 644 ssl/ace.cert.pem
    chmod 644 ssl/ca-chain-combined.cert.pem
    chmod 644 ssl/ca-chain.cert.pem

    cp ssl/ace.key.pem ssl/mysql.key.pem
    cp ssl/ace.cert.pem ssl/mysql.cert.pem

    chmod 644 ssl/mysql.key.pem
    chmod 644 ssl/mysql.cert.pem
fi

# prepare SQL files

if [ ! -f /docker-entrypoint-initdb.d/done ]
then
    bin/initialize_database.py 
fi

# TOOD
# initialize gitconfig

#
# make sure all these directories and files exist
#

for dir in \
    data/error_reports \
    data/logs \
    data/var \
    data/scan_failures \
    data/storage \
    data/stats/modules/ace \
    data/archive/email \
    data/archive/smtp_stream \
    data/archive/office \
    data/archive/ole \
    data/work \
    data/etc \
    data/ssh \
    data/external/analyst-data
do
    if [ ! -d $dir ]
    then
        echo "creating directory $dir"
        mkdir -p $dir
    fi
done

for path in data/etc/site_tags.csv data/etc/ssdeep_hashes
do
	if [ ! -e "${path}" ]; then touch "${path}"; fi
done

if [ ! -e data/ssh/id_rsa ]
then
    echo "creating SSH key"
    ssh-keygen -t rsa -b 4096 -f data/ssh/id_rsa -N ""
fi

bin/initialize_auth.sh

# TODO get rid of these
if [ ! -e data/etc/organization.json ]; then echo '{}' > data/etc/organization.json; fi
if [ ! -e data/etc/local_networks.csv ]; then echo 'Indicator,Indicator_Type' > data/etc/local_networks.csv; fi

# make sure we've got our SSH creds for github
#if [ ! -e ~/.ssh/id_rsa ]
#then
    #mkdir -p ~/.ssh && tar -C ~/.ssh -zxf mnt/ssh.$ACE_TARGET/ssh.creds.tar.gz && chmod 400 ~/.ssh/id_rsa
#fi

#if [ ! -e ~/.ssh/known_hosts ]
#then
    #cp mnt/ssh.$ACE_TARGET/known_hosts ~/.ssh/known_hosts
#fi