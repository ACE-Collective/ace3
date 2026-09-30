# vim: sw=4:ts=4:et:cc=120
#
# utility functions to use the brocess databases

from saq.database import get_db_connection

def query_brocess_by_dest_ipv4(ipv4):
    with get_db_connection(name='brocess') as db:
        cursor = db.cursor()
        cursor.execute('SELECT SUM(numconnections) FROM connlog WHERE destip = INET_ATON(%s)', (ipv4,))
    
        for row in cursor:
            count = row[0]
            return int(count) if count is not None else 0

        raise RuntimeError("failed to return a row for sum() query operation !?")

def query_brocess_by_email_conversation(source_email_address, dest_email_address):
    with get_db_connection(name='brocess') as db:
        cursor = db.cursor()
        cursor.execute('SELECT SUM(numconnections) FROM smtplog WHERE source = %s AND destination = %s', (
                   source_email_address, dest_email_address,))
    
        for row in cursor:
            count = row[0]
            return int(count) if count is not None else 0

        raise RuntimeError("failed to return a row for sum() query operation !?")

def query_brocess_by_source_email(source_email_address):
    with get_db_connection(name='brocess') as db:
        cursor = db.cursor()
        cursor.execute('SELECT SUM(numconnections) FROM smtplog WHERE source = %s', (source_email_address,))
    
        for row in cursor:
            count = row[0]
            return int(count) if count is not None else 0

        raise RuntimeError("failed to return a row for sum() query operation !?")
