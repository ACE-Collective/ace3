#!/usr/bin/env bash
#
# ensures all the files and directories that are needed exist
# and waits for the database connection to become available
# this file is sourced from every other startup file
#

source /opt/ace/bin/initialize-environment.sh

# NOTE in the default docker-compose.yml the ssl directory is bind-mounted
# once this runs once you can import the certificates into your system/browser
# do we need to create fake ssl certificates?
if [ -z "$(ls -A ssl 2>/dev/null)" ]
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
        -subj "/C=US/ST=Ohio/L=Springfield/O=CompanyName/OU=CompanySectionName/CN=ace" \
        -addext "subjectAltName=DNS:ace,DNS:ace-db,DNS:ace-db-readonly,DNS:ace-http-external,DNS:ace-http,DNS:garagehq,DNS:phishkit,DNS:qdrant,DNS:rabbitmq,DNS:redis,DNS:localhost,IP:127.0.0.1"

    # create the client certificate for testing external access
    echo "creating client certificate and key"
    
    # create client private key
    openssl genrsa -out ssl/ace.client.key.pem 2048
    
    # create client certificate signing request
    openssl req -new \
        -key ssl/ace.client.key.pem \
        -out ssl/ace.client.csr \
        -subj "/C=US/ST=Ohio/L=Springfield/O=CompanyName/OU=CompanySectionName/CN=ace-client"
    
    # sign client certificate with the self-signed certificate (acting as CA)
    openssl x509 -req \
        -in ssl/ace.client.csr \
        -CA ssl/ace.cert.pem \
        -CAkey ssl/ace.key.pem \
        -CAcreateserial \
        -out ssl/ace.client.cert.pem \
        -days 3650 \
        -sha256

    # make a p12 for macos clients (no export password)
    openssl pkcs12 -passout pass: -export -inkey ssl/ace.client.key.pem -in ssl/ace.client.cert.pem -out ssl/ace.client.p12
    
    # clean up
    rm ssl/ace.client.csr
    
    # the self-signed certificate is also the CA chain
    cp ssl/ace.cert.pem ssl/ca-chain.cert.pem

    # these are the same as the ace certs but need looser perms for mysql user
    # insecure but this is for a local dev environment
    cp ssl/ace.key.pem ssl/mysql.key.pem
    cp ssl/ace.cert.pem ssl/mysql.cert.pem

    # Set proper permissions for SSL files
    chmod 600 ssl/ace.client.key.pem
    chmod 644 ssl/ace.client.cert.pem
    chmod 600 ssl/ace.key.pem
    chmod 644 ssl/ace.cert.pem
    chmod 644 ssl/ca-chain.cert.pem
    chmod 644 ssl/mysql.key.pem # <-- loose perms
    chmod 644 ssl/mysql.cert.pem
fi

# if we're missing any of the required authentication credentials then we create them here
# this is for someone just standing up a quick dev environment to test this out
# production systems should have these values defined

bin/initialize_auth.sh

# prepare SQL files

if [ ! -f /docker-entrypoint-initdb.d/done ]
then
    bin/initialize_database.py /docker-entrypoint-initdb.d --primary-database ${ACE_DB_HOST:-ace-db}
fi

if [ ! -f /ace-sql-readonly/done ]
then
    bin/initialize_database.py /ace-sql-readonly --type replica --primary-database ${ACE_DB_HOST:-ace-db}
fi

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

# TODO get rid of these
if [ ! -e data/etc/organization.json ]; then echo '{}' > data/etc/organization.json; fi
if [ ! -e data/etc/local_networks.csv ]; then echo 'Indicator,Indicator_Type' > data/etc/local_networks.csv; fi
