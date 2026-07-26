# Shared MySQL connection settings for the bin/ database scripts.
#
# Credentials come from the generated superuser defaults file (written by
# bin/initialize_database.py::create_mysql_defaults_file) which carries host,
# user and password. The server requires TLS against our own CA, so --ssl-ca
# is added here too. See bin/db-root for the same invocation.
#
# NOTE $options must always be the FIRST argument to mysql/mysqladmin/mysqldump:
# --defaults-file is only honored in that position.

mysql_defaults_file="${MYSQL_DEFAULTS_FILE:-/docker-entrypoint-initdb.d/mysql_defaults.root}"
mysql_ssl_ca="${MYSQL_SSL_CA:-${SAQ_HOME:-/opt/ace}/ssl/ca-chain.cert.pem}"

if [ ! -e "$mysql_defaults_file" ]
then
    echo "missing mysql defaults file $mysql_defaults_file" >&2
    exit 1
fi

if [ ! -e "$mysql_ssl_ca" ]
then
    echo "missing ssl ca $mysql_ssl_ca" >&2
    exit 1
fi

prefix=""
options="--defaults-file=$mysql_defaults_file --ssl-ca=$mysql_ssl_ca"
