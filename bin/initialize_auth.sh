#!/usr/bin/env bash

#
# some of the built-in services require authentication to be set up
# so we initialize the system with random passwords
# and store the results in the auth volume
#

# I obviously used AI to create this function
genpw() {

    local min="$1" max="$2"
    if [[ -z "$min" || -z "$max" || "$min" -le 0 || "$max" -lt "$min" ]]; then
        echo "Usage: genpw MIN MAX   (where MIN>=1 and MAX>=MIN)" >&2
        return 1
    fi

    # Uniform random length in [min, max] using /dev/urandom + rejection sampling
    local range=$((max - min + 1))
    local r limit L
    local TWO32=4294967296  # 2^32
  
    while :; do
        # Read an unsigned 32-bit integer
        r=$(od -An -N4 -tu4 < /dev/urandom | tr -d ' ')
        # Largest multiple of range less than 2^32, avoids modulo bias
        limit=$(( (TWO32 / range) * range ))
        (( r < limit )) && { L=$(( min + (r % range) )); break; }
    done

    # Generate L characters from a safe, shell-friendly alphabet
    # Put '-' at the end so it's not interpreted as a range by tr.
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$L"
}


# the ace-auth volume is mounted at /auth
for dir in /auth/passwords /auth/etc /auth/keys
do
    if [ ! -d $dir ]
    then
        mkdir -p $dir
    fi
done

if [ ! -f /auth/passwords/ace-user ]
then
    echo "initializing mysql ace-user authentication"
    if [ -z "$ACE_DB_USER_PASSWORD" ]
    then
        echo "generating random password for mysql ace-user"
        ACE_DB_USER_PASSWORD=$(genpw 12 16)
        echo "generated password for mysql ace-user: ${ACE_DB_USER_PASSWORD}"
    fi

    echo "${ACE_DB_USER_PASSWORD}" > /auth/passwords/ace-user
fi

if [ ! -f /auth/passwords/ace-superuser ]
then
    echo "initializing mysql superuser authentication"
    if [ -z "$ACE_SUPERUSER_DB_USER_PASSWORD" ]
    then
        echo "generating random password for mysql ace-superuser"
        ACE_SUPERUSER_DB_USER_PASSWORD=$(genpw 12 16)
        echo "generated password for mysql ace-superuser: ${ACE_SUPERUSER_DB_USER_PASSWORD}"
    fi

    echo "${ACE_SUPERUSER_DB_USER_PASSWORD}" > /auth/passwords/ace-superuser
fi

if [ ! -d /auth/etc/redis ]
then
    echo "initializing redis authentication"
    mkdir -p /auth/etc/redis
    echo "aclfile /auth/etc/redis/custom_aclfile.acl" > /auth/etc/redis/redis.conf
    # TODO come back to this idea, ran into issues with some of the clients
    # Add TLS configuration
    #echo "port 0" >> /auth/etc/redis/redis.conf
    #echo "tls-port 6379" >> /auth/etc/redis/redis.conf
    #echo "tls-cert-file /opt/ace/ssl/ace.cert.pem" >> /auth/etc/redis/redis.conf
    #echo "tls-key-file /opt/ace/ssl/ace.key.pem" >> /auth/etc/redis/redis.conf
    #echo "tls-ca-cert-file /opt/ace/ssl/ca-chain.cert.pem" >> /auth/etc/redis/redis.conf
    #echo "tls-protocols \"TLSv1.2 TLSv1.3\"" >> /auth/etc/redis/redis.conf
    #echo "tls-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256" >> /auth/etc/redis/redis.conf
    #echo "tls-prefer-server-ciphers yes" >> /auth/etc/redis/redis.conf
    
    if [ -z "$REDIS_PASSWORD" ]
    then
        echo "generating random password for redis"
        REDIS_PASSWORD=$(genpw 12 16)
        echo "generated password for redis: ${REDIS_PASSWORD}"
    fi
    echo "user ace3 on allkeys allchannels allcommands >${REDIS_PASSWORD} " > /auth/etc/redis/custom_aclfile.acl
    echo "user default off nopass nocommands" >> /auth/etc/redis/custom_aclfile.acl
    echo "${REDIS_PASSWORD}" > /auth/passwords/redis
fi

if [ ! -d /auth/etc/garagehq ]
then
    echo "initializing garagehq authentication"
    mkdir -p /auth/etc/garagehq
    if [ -z "$GARAGEHQ_RPC_SECRET" ]
    then
        echo "generating random rpc secret for garagehq"
        GARAGEHQ_RPC_SECRET=$(openssl rand -hex 32)
    fi

    if [ -z "$GARAGEHQ_ADMIN_TOKEN" ]
    then
        echo "generating random admin token for garagehq"
        GARAGEHQ_ADMIN_TOKEN=$(openssl rand -base64 32)
    fi

    if [ -z "$GARAGEHQ_METRICS_TOKEN" ]
    then
        echo "generating random metrics token for garagehq"
        GARAGEHQ_METRICS_TOKEN=$(openssl rand -base64 32)
    fi

    echo "${GARAGEHQ_RPC_SECRET}" > /auth/passwords/garagehq-rpc-secret
    echo "${GARAGEHQ_ADMIN_TOKEN}" > /auth/passwords/garagehq-admin-token
    echo "${GARAGEHQ_METRICS_TOKEN}" > /auth/passwords/garagehq-metrics-token

    cat > /auth/etc/garagehq/garage.toml <<EOF
metadata_dir = "/data/meta"
data_dir = "/data/data"
db_engine = "sqlite"

replication_factor = 1

rpc_bind_addr = "[::]:3901"
rpc_public_addr = "127.0.0.1:3901"
rpc_secret = "${GARAGEHQ_RPC_SECRET}"

[s3_api]
s3_region = "garage"
api_bind_addr = "[::]:3900"
root_domain = ".s3.garage.localhost"

[s3_web]
bind_addr = "[::]:3902"
root_domain = ".web.garage.localhost"
index = "index.html"

[k2v_api]
api_bind_addr = "[::]:3904"

[admin]
api_bind_addr = "[::]:3903"
admin_token = "${GARAGEHQ_ADMIN_TOKEN}"
metrics_token = "${GARAGEHQ_METRICS_TOKEN}"
EOF
fi

if [ ! -d /auth/etc/rabbitmq ]
then
    echo "initializing rabbitmq authentication"
    mkdir -p /auth/etc/rabbitmq
    if [ -z "$RABBITMQ_PASSWORD" ]
    then
        echo "generating random password for rabbitmq"
        RABBITMQ_PASSWORD=$(genpw 12 16)
        echo "generated password for rabbitmq: ${RABBITMQ_PASSWORD}"
    fi

    echo "${RABBITMQ_PASSWORD}" > /auth/passwords/rabbitmq
fi

if [ ! -f /auth/passwords/qdrant ]
then
    echo "initializing qdrant authentication"
    if [ -z "$QDRANT_API_KEY" ]
    then
        echo "generating random api key for qdrant"
        QDRANT_API_KEY=$(genpw 12 16)
        echo "generated api key for qdrant: ${QDRANT_API_KEY}"
    fi

    echo "${QDRANT_API_KEY}" > /auth/passwords/qdrant
fi

if [ ! -f /auth/passwords/ace-api-key ]
then
    echo "initializing ace api keys"
    if [ -z "$ACE_API_KEY" ]
    then
        ACE_API_KEY=$(cat /proc/sys/kernel/random/uuid | tr '[:upper:]' '[:lower:]')
    fi

    ACE_API_KEY_SHA256=$(echo -ne $ACE_API_KEY | openssl sha256 -r | awk '{print $1}')
    echo "${ACE_API_KEY}" > /auth/passwords/ace-api-key
    echo "${ACE_API_KEY_SHA256}" > /auth/passwords/ace-api-key-sha256
fi

if [ ! -f /auth/keys/flask-secret-key ]
then
    if [ -z "$FLASK_SECRET_KEY" ]
    then
        echo "initializing flask secret key"
        FLASK_SECRET_KEY=$(cat /proc/sys/kernel/random/uuid | tr '[:upper:]' '[:lower:]')
    fi

    echo "${FLASK_SECRET_KEY}" > /auth/keys/flask-secret-key
fi
