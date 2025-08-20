import logging
import os
from typing import Optional

from saq.cli.cli_main import get_cli_subparsers
from saq.storage.factory import get_storage_system

#
# cli
#

storage_parser = get_cli_subparsers().add_parser("storage", help="Storage operations for ACE.")
storage_sp = storage_parser.add_subparsers(dest="storage_cmd")

def cli_list_buckets(args) -> int:
    """List all available storage buckets."""
    try:
        storage = get_storage_system()
        buckets = storage.list_buckets()
        
        if not buckets:
            print("No buckets found.")
        else:
            print("Available buckets:")
            for bucket in buckets:
                print(f"  {bucket}")
        
        return os.EX_OK
    except Exception as e:
        logging.error(f"Failed to list buckets: {e}")
        print(f"Error: {e}")
        return os.EX_OSERR

storage_list_buckets_parser = storage_sp.add_parser("list-buckets", help="List all available storage buckets.")
storage_list_buckets_parser.set_defaults(func=cli_list_buckets)

def cli_list_objects(args) -> int:
    """List objects in a storage bucket."""
    try:
        storage = get_storage_system()
        objects = storage.list_objects(args.bucket, recursive=True, prefix=args.prefix)
        
        if not objects:
            print(f"No objects found in bucket '{args.bucket}'" + (f" with prefix '{args.prefix}'" if args.prefix else ""))
        else:
            print(f"Objects in bucket '{args.bucket}'" + (f" with prefix '{args.prefix}'" if args.prefix else ""))
            for obj in objects:
                print(f"  {obj}")
        
        return os.EX_OK
    except Exception as e:
        logging.error(f"Failed to list objects in bucket '{args.bucket}': {e}")
        print(f"Error: {e}")
        return os.EX_OSERR

storage_list_objects_parser = storage_sp.add_parser("list-objects", help="List objects in a storage bucket.")
storage_list_objects_parser.add_argument("bucket", help="The bucket to list objects from.")
storage_list_objects_parser.add_argument("-p", "--prefix", help="Optional prefix to filter objects by.")
storage_list_objects_parser.set_defaults(func=cli_list_objects)

def cli_download(args) -> int:
    """Download a file from storage."""
    try:
        storage = get_storage_system()
        
        # Determine local file path
        if args.local_file_path:
            local_path = args.local_file_path
        else:
            # Use the remote file name as local file name
            local_path = os.path.basename(args.remote_file_path)
        
        # Check if local file already exists
        if os.path.exists(local_path) and not args.force:
            print(f"Error: Local file '{local_path}' already exists. Use --force to overwrite.")
            return os.EX_CANTCREAT
        
        print(f"Downloading {args.bucket}/{args.remote_file_path} to {local_path}...")
        storage.download_file(args.bucket, args.remote_file_path, local_path)
        print(f"Successfully downloaded to {local_path}")
        
        return os.EX_OK
    except Exception as e:
        logging.error(f"Failed to download {args.bucket}/{args.remote_file_path}: {e}")
        print(f"Error: {e}")
        return os.EX_OSERR

storage_download_parser = storage_sp.add_parser("download", help="Download a file from storage.")
storage_download_parser.add_argument("bucket", help="The bucket to download from.")
storage_download_parser.add_argument("remote_file_path", help="The remote file path to download.")
storage_download_parser.add_argument("local_file_path", nargs="?", help="The local file path to save to. If not specified, uses the remote file name.")
storage_download_parser.add_argument("-f", "--force", action="store_true", help="Overwrite existing local file.")
storage_download_parser.set_defaults(func=cli_download)

def cli_upload(args) -> int:
    """Upload a file to storage."""
    try:
        storage = get_storage_system()
        
        # Check if local file exists
        if not os.path.exists(args.local_file_path):
            print(f"Error: Local file '{args.local_file_path}' does not exist.")
            return os.EX_NOINPUT
        
        # Determine remote file path
        if args.remote_file_path:
            remote_path = args.remote_file_path
        else:
            # Use the local file name as remote file name
            remote_path = os.path.basename(args.local_file_path)
        
        print(f"Uploading {args.local_file_path} to {args.bucket}/{remote_path}...")
        storage.upload_file(args.local_file_path, args.bucket, remote_path)
        print(f"Successfully uploaded to {args.bucket}/{remote_path}")
        
        return os.EX_OK
    except Exception as e:
        logging.error(f"Failed to upload {args.local_file_path} to {args.bucket}: {e}")
        print(f"Error: {e}")
        return os.EX_OSERR

storage_upload_parser = storage_sp.add_parser("upload", help="Upload a file to storage.")
storage_upload_parser.add_argument("local_file_path", help="The local file path to upload.")
storage_upload_parser.add_argument("bucket", help="The bucket to upload to.")
storage_upload_parser.add_argument("remote_file_path", nargs="?", help="The remote file path. If not specified, uses the local file name.")
storage_upload_parser.set_defaults(func=cli_upload)
