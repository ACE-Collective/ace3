#!/usr/bin/env python3
#
# initializes your docker development environment by creating
# random passwords for the database connections
# and then updating the configuration files with those passwords
#

import os
import os.path
import random
import re
import shutil
import string
import sys

import yaml

def generate_password() -> str:
    return "".join(random.choices(string.ascii_letters, k=random.randint(23, 32))) 

def get_user_password() -> str:
    # if the password is set in the environment, use it
    user_password = os.environ.get("ACE_DB_USER_PASSWORD")
    if not user_password:
        # otherwise load the password from the auth directory
        with open("/auth/passwords/ace-user", "r") as fp:
            user_password = fp.read().strip()

    if not user_password:
        raise RuntimeError("unable to load password for ace-user\n")

    return user_password

def get_admin_password() -> str:
    admin_password = os.environ.get("ACE_SUPERUSER_DB_USER_PASSWORD")
    if not admin_password:
        # otherwise load the password from the auth directory
        with open("/auth/passwords/ace-superuser", "r") as fp:
            admin_password = fp.read().strip()

    if not admin_password:
        raise RuntimeError("unable to load password for ace-superuser\n")

    return admin_password

def create_mysql_defaults_file(target_path: str, user: str, primary_database: str, password: str):
    with open(target_path, "w") as fp:
        fp.write(f"""[client]
host={primary_database}
user={user}
password={password}
""")

def initialize_replica(target_dir: str, primary_database: str):
    admin_password = get_admin_password()

    target_path = os.path.join(target_dir, "98-configure-and-start-replica.sql")
    with open(target_path, "w") as fp:
        fp.write(f"""
        CHANGE REPLICATION SOURCE TO
        SOURCE_HOST = '{primary_database}',
        SOURCE_PORT = 3306,
        SOURCE_USER = 'ace-superuser',
        SOURCE_PASSWORD = '{admin_password}',
        SOURCE_AUTO_POSITION = 1,
        SOURCE_SSL = 1,
        SOURCE_SSL_CA = '/opt/ace/ssl/ca-chain.cert.pem';
        START REPLICA;
        """)

    print(f"created {target_path}")

    target_path = os.path.join(target_dir, "mysql_defaults")
    create_mysql_defaults_file(target_path, "ace-user", primary_database, get_user_password())
    print(f"created {target_path}")

def initialize_sql(target_dir: str, primary_database: str):
    source_dir = "sql"
    #target_dir = "/docker-entrypoint-initdb.d"
    print(f"copying {source_dir} to {target_dir}")
    shutil.copytree(source_dir, target_dir, dirs_exist_ok=True)

    user_password = get_user_password()
    source_path = os.path.join(target_dir, "templates", "create_db_user.sql")
    target_path = os.path.join(target_dir, "70-create-db-user.sql")
    with open(source_path, 'r') as fp_in:
        sql = fp_in.read().replace("ACE_DB_USER_PASSWORD", user_password)
        with open(target_path, "w") as fp:
            fp.write(sql)

        print(f"created {target_path}")

    target_path = os.path.join(target_dir, "mysql_defaults")
    create_mysql_defaults_file(target_path, "ace-user", primary_database, user_password)
    print(f"created {target_path}")

    # same for the admin password
    admin_password = os.environ.get("ACE_SUPERUSER_DB_USER_PASSWORD")
    if not admin_password:
        # otherwise load the password from the auth directory
        with open("/auth/passwords/ace-superuser", "r") as fp:
            admin_password = fp.read().strip()

    if not admin_password:
        sys.stderr.write("ERROR: unable to load password for ace-superuser\n")
        sys.exit(1)

    source_path = os.path.join(source_dir, "templates", "create_db_super_user.sql")
    target_path = os.path.join(target_dir, "71-create-db-super-user.sql")
    with open(source_path, "r") as fp_in:
        sql = fp_in.read().replace("ACE_SUPERUSER_DB_USER_PASSWORD", admin_password)
        with open(target_path, "w") as fp:
            fp.write(sql)

    print(f"created {target_path}")

    target_path = os.path.join(target_dir, "mysql_defaults.root")
    create_mysql_defaults_file(target_path, "ace-superuser", primary_database, admin_password)
    print(f"created {target_path}")

    target_path = os.path.join(target_dir, "saq.database.passwords.yaml")
    database_passwords = {
        "database_ace": { "password": user_password },
        "database_collection": { "password": user_password },
        "database_email_archive": { "password": user_password },
        "database_brocess": { "password": user_password },
    }
    with open(target_path, "w") as fp:
        yaml.dump(database_passwords, fp, indent=2)

    print(f"created {target_path}")

    for src_sql, dest_sql in [
        ("01-ace.sql", "21-ace-unittest.sql"),
        ("02-email-archive.sql", "22-email-archive-unittest.sql"),
        ("03-brocess.sql", "23-brocess-unittest.sql"),
        ("05-amc.sql", "25-amc-unittest.sql"), ]:
        with open(os.path.join(source_dir, src_sql), "r") as fp_in:
            with open(os.path.join(target_dir, dest_sql), "w") as fp_out:
                for line in fp_in:
                    if line.startswith("CREATE DATABASE IF NOT EXISTS `") \
                    or line.startswith("ALTER DATABASE `") \
                    or line.startswith("USE `"):
                        line = re.sub(r'`([^`]+)`', r'`\1-unittest`', line)

                    fp_out.write(line)

    # this sucks -- a few of the integration tests require yet another ace database
    # XXX fix me!
    for src_sql, dest_sql in [
        ("01-ace.sql", "211-ace-unittest-2.sql"), ]:
        with open(os.path.join(source_dir, src_sql), "r") as fp_in:
            with open(os.path.join(target_dir, dest_sql), "w") as fp_out:
                for line in fp_in:
                    if line.startswith("CREATE DATABASE IF NOT EXISTS `") \
                    or line.startswith("ALTER DATABASE `") \
                    or line.startswith("USE `"):
                        line = re.sub(r'`([^`]+)`', r'`\1-unittest-2`', line)

                    fp_out.write(line)

    target_path = os.path.join(target_dir, "done")
    with open(target_path, "w") as fp:
        fp.write("done")

def ignore():

    # do we have proxy settings?
    http_proxy = os.environ.get('http_proxy')
    https_proxy = os.environ.get('https_proxy')
    if os.path.exists('proxy_settings.txt'):
        with open('proxy_settings.txt', 'r') as fp:
            proxy_settings = fp.read().strip()
            http_proxy = proxy_settings
            https_proxy = proxy_settings
            print("using proxy settings from proxy_settings.txt")

    if http_proxy is None and https_proxy is None:
        use_proxy = input("There is no proxy set. Are you using a proxy? (y/N)")
        if use_proxy.strip().lower() == 'y':
            print("Enter your proxy information.")
            print("It looks something like this:")
            print("http://USERNAME:PASSWORD@PROXY.HOST.NAME:8080")
            print("Make sure your PASSWORD is urlencoded.")
            http_proxy = input("> ").strip()
            https_proxy = http_proxy
            save = input("Do you want me to save this so you don't have to type it in again? (y/N)")
            if save.strip().lower() == 'y':
                with open('proxy_settings.txt', 'w') as fp:
                    fp.write(http_proxy)

    target_dir = os.path.join('docker', 'provision', 'ace', 'etc', 'apt')
    os.makedirs(target_dir, exist_ok=True)
    target_path = os.path.join(target_dir, 'proxy.conf')

    if http_proxy and https_proxy:
        write_proxy_settings = False
        if os.path.exists(target_path):
            with open(target_path, 'r') as fp:
                settings = fp.read()
                if http_proxy not in settings:
                    write_proxy_settings = True
        else:
            write_proxy_settings = True

        if write_proxy_settings:
            with open(target_path, 'w') as fp:
                print(f"writing proxy settings to {target_path}")
                fp.write(f"""Acquire::http::Proxy "{http_proxy}";
Acquire::https::Proxy "{https_proxy}";
""")
    
    if not os.path.exists(target_path):
        with open(target_path, 'w') as fp:
            pass

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("target_dir", help="Ends up as /docker-entrypoint-initdb.d in the mysql container")
    parser.add_argument("--type", help="Type of database to initialize", choices=["primary", "replica"])
    parser.add_argument("--primary-database", help="The hostname of the primary database", default="ace-db")
    args = parser.parse_args()
    if args.type == "replica":
        initialize_replica(args.target_dir, args.primary_database)
    else:
        initialize_sql(args.target_dir, args.primary_database)
