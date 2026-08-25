import getpass
import json
import logging
import sys

from saq.cli.cli_main import get_cli_subparsers


encryption_parser = get_cli_subparsers().add_parser('encryption', aliases=['enc'],
    help="Encryption management commands.")
encryption_sp = encryption_parser.add_subparsers(dest='enc_cmd')

def set_encryption_password(args):
    from saq.crypto import set_encryption_password, get_aes_key, InvalidPasswordError, encryption_key_set
    while True:
        current_password = None
        if encryption_key_set() and not args.overwrite:
            current_password = getpass.getpass("Enter the CURRENT encryption password:")
            try:
                get_aes_key(current_password)
            except InvalidPasswordError:
                print("ERROR: invalid password")
                print("if you can't remember you can use the --overwrite option")
                print("but then you won't be able to access anything you've already encrypted")
                continue
            
        if args.password is None:
            password = getpass.getpass("enter the new encryption password:")
            password_2 = getpass.getpass("enter the new encryption password again for verification:")
        else:
            password = password_2 = args.password

        if password != password_2:
            logging.error("passwords do not match")
            continue

        break

    key = None
    if args.key:
        while True:
            key = getpass.getpass("enter the primary encryption key password:")
            key_2 = getpass.getpass("enter the primary encryption key password again for verification:")

            if key != key_2:
                logging.error("passwords do not match")
                continue

            break

        from Crypto.Hash import SHA256
        h = SHA256.new()
        h.update(key.encode())
        key = h.digest()

    set_encryption_password(password, old_password=current_password, key=key)
    sys.exit(0)

# XXX DEPRECATED
set_encryption_password_parser = get_cli_subparsers().add_parser('set-encryption-password',
    help="Sets the password used to encrypt and decrypt archived emails.")
set_encryption_password_parser.add_argument('-o', '--overwrite', default=False, action='store_true',
    help="Overwrites an existing password without prompting.")
set_encryption_password_parser.add_argument('-k', '--key', default=False, action='store_true',
    help="Use the sha256 hash of a string as the primary encryption key. The input is prompted for.")
set_encryption_password_parser.set_defaults(func=set_encryption_password)

set_encryption_password_parser = encryption_sp.add_parser('set',
    help="Sets the password used to encrypt and decrypt archived emails.")
set_encryption_password_parser.add_argument('-o', '--overwrite', default=False, action='store_true',
    help="Overwrites an existing password without prompting.")
set_encryption_password_parser.add_argument('-k', '--key', default=False, action='store_true',
    help="Use the sha256 hash of a string as the primary encryption key. The input is prompted for.")
set_encryption_password_parser.add_argument('-p', '--password',
    help="Use this for the password instead of prompting. Don't use this option unless you have a good reason to.")
set_encryption_password_parser.set_defaults(func=set_encryption_password)

def test_encryption_password(args):
    import saq.crypto
    if not saq.crypto.encryption_key_set():
        logging.warning("encryption key is not set yet")
        sys.exit(2)

    if args.password is None:
        password = getpass.getpass("Enter the decryption password:")
    else:
        password = args.password

    try:
        saq.crypto.get_aes_key(password)
        logging.info("password OK")
    except saq.crypto.InvalidPasswordError:
        logging.error("invalid password")
        sys.exit(1)

    sys.exit(0)

test_encryption_password_parser = encryption_sp.add_parser('test',
    help="Tests the given password to see if it matches what is currently set as the encryption password.")
test_encryption_password_parser.add_argument('-p', '--password',
        help="Provide the password on the command line. Only recommended for automation purposes.")
test_encryption_password_parser.set_defaults(func=test_encryption_password)

def encrypt_file(args):
    from saq.crypto import encrypt

    password = None
    if args.password:
        password = args.password
    elif args.prompt:
        password = getpass.getpass("enter encryption password: ")
        verify = getpass.getpass("verify encryption password: ")
        if password != verify:
            print("passwords do not match")
            sys.exit(1)

    encrypt(args.source_path, args.target_path, password=password)
    sys.exit(0)

encrypt_file_parser = encryption_sp.add_parser('encrypt',
    help="Encrypts the given file with the password set with set-encryption-password.")
encrypt_file_parser.add_argument('source_path', help="The file to encrypt from.")
encrypt_file_parser.add_argument('target_path', help="The file to saved the decrypted data to.")
encrypt_file_parser.add_argument('--password', help="Use the given password to encrypt the file.")
encrypt_file_parser.add_argument('--prompt', action='store_true', default=False, 
    help="Prompt for the password to use to encrypt the file.")
encrypt_file_parser.set_defaults(func=encrypt_file)

def decrypt_file(args):
    from saq.crypto import decrypt

    password = None
    if args.password:
        password = args.password
    elif args.prompt:
        password = getpass.getpass("enter decryption password: ")

    decrypt(args.source_path, args.target_path, password=password)
    sys.exit(0)

decrypt_file_parser = encryption_sp.add_parser('decrypt',
    help="Decrypts the given file with the password set with set-decryption-password.")
decrypt_file_parser.add_argument('source_path', help="The file to decrypt from.")
decrypt_file_parser.add_argument('target_path', help="The file to saved the decrypted data to.")
decrypt_file_parser.add_argument('--password', help="Use the given password to decrypt the file.")
decrypt_file_parser.add_argument('--prompt', help="Prompt for the password to use to decrypt the file.")
decrypt_file_parser.set_defaults(func=decrypt_file)

config_encryption_parser = encryption_sp.add_parser('config',
    help="Configuration encryption management commands.")
config_encryption_sp = config_encryption_parser.add_subparsers(dest='config_enc_cmd')

def set_encrypted_password(args):
    from saq.environment import get_global_runtime_settings

    if get_global_runtime_settings().encryption_key is None:
        logging.error("missing encryption password (use the -p option or start the ecs service)\n")
        sys.exit(1)

    if args.load_from_file:
        with open(args.load_from_file, "r") as fp:
            password = fp.read().strip()
    elif args.value:
        password = args.value
    else:
        while True:
            password = getpass.getpass("Enter the data to be encrypted and stored:")
            password_2 = getpass.getpass("Re-enter the value for verification:")

            if password != password_2:
                logging.error("passwords do not match, try again")
                continue

            break

    from saq.configuration.encryption import encrypt_password
    encrypt_password(args.key, password)
    sys.exit(0)

set_encrypted_password_parser = config_encryption_sp.add_parser('set',
    help="Set a password in the system, storing the value encrypted in the database. You will be prompted for the password.")
set_encrypted_password_parser.add_argument('key',
    help="The key (name) of the password.")
set_encrypted_password_parser.add_argument('--value', help="The value to store. Prompted if not supplied.")
set_encrypted_password_parser.add_argument('--load-from-file', help="A file that contains the value to use. Trailing whitespace is ignored.")
set_encrypted_password_parser.set_defaults(func=set_encrypted_password)

def list_encrypted_passwords(args):
    from saq.configuration.encryption import export_encrypted_passwords
    encrypted_passwords = export_encrypted_passwords()
    if not encrypted_passwords:
        print("no passwords have been encrypted")
        sys.exit(0)

    for key, value in encrypted_passwords.items():
        if value is None:
            value = "<encrypted>"

        print(f"{key} = {value}")

    sys.exit(0)

list_encrypted_passwords_parser = config_encryption_sp.add_parser('list',
    help="Lists the encrypted passwords.")
list_encrypted_passwords_parser.set_defaults(func=list_encrypted_passwords)

# XXX DEPRECATED
list_encrypted_passwords_parser = get_cli_subparsers().add_parser('list-encrypted-passwords',
    help="Lists the encrypted passwords.")
list_encrypted_passwords_parser.set_defaults(func=list_encrypted_passwords)

def delete_encrypted_password(args):
    from saq.configuration.encryption import delete_password
    if delete_password(args.key):
        print("password deleted")
    else:
        print("ERROR: unable to delete password")

    sys.exit(0)

delete_encrypted_password_parser = config_encryption_sp.add_parser('delete',
    help="Deletes a given encrypted password.")
delete_encrypted_password_parser.add_argument('key',
    help="The name of the password to delete.")
delete_encrypted_password_parser.set_defaults(func=delete_encrypted_password)

# XXX DEPRECATED
delete_encrypted_password_parser = get_cli_subparsers().add_parser('delete-encrypted-password',
    help="Deletes a given encrypted password.")
delete_encrypted_password_parser.add_argument('key',
    help="The name of the password to delete.")
delete_encrypted_password_parser.set_defaults(func=delete_encrypted_password)

def export_encrypted_passwords(args):
    import saq.configuration.encryption

    if args.file == '-':
        fp = sys.stdout
    else:
        fp = open(args.file, 'w')

    json.dump(saq.configuration.encryption.export_encrypted_passwords(), fp)
    fp.write('\n')
    fp.close()
    sys.exit(0)

export_encrypted_passwords_parser = config_encryption_sp.add_parser('export',
    help="Exports the encrypted passwords to JSON.")
export_encrypted_passwords_parser.add_argument('file',
    help="""The name of the file to store the JSON. 
            Use a file name of - to export to stdout.""")
export_encrypted_passwords_parser.set_defaults(func=export_encrypted_passwords)

def import_encrypted_passwords(args):
    import saq.configuration.encryption

    if args.file == '-':
        fp = sys.stdin
    else:
        fp = open(args.file, 'r')

    saq.configuration.encryption.import_encrypted_passwords(json.load(fp))
    fp.close()
    sys.exit(0)

import_encrypted_passwords_parser = config_encryption_sp.add_parser('import',
    help="Imports the encrypted passwords JSON generated by the export command.")
import_encrypted_passwords_parser.add_argument('file',
    help="""The name of the JSON export. 
            Use a file name of - to import from stdin.""")
import_encrypted_passwords_parser.set_defaults(func=import_encrypted_passwords)
