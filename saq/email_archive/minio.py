import logging
import os
import tempfile
from typing import Optional

from minio import Minio
from minio.error import S3Error
from saq.configuration.config import get_config_value
from saq.constants import CONFIG_EMAIL_ARCHIVE, CONFIG_EMAIL_ARCHIVE_S3_BUCKET, CONFIG_EMAIL_ARCHIVE_S3_CONFIG
from saq.email_archive.local import EmailArchiveLocal
from saq.storage.minio import get_minio_client

#
# right now we're trying to stay backwards compatible with the local implementation
# as much as possible
#

def _extract_sha256_from_file_name(file_path: str) -> str:
    """Given a local email archive file path, extract the sha256 hash from the file name."""
    # see get_archive_path_by_hash
    # file name should be sha256_hash.lower().gz.e
    return os.path.basename(file_path).split('.')[0]

def _get_email_archive_minio_client() -> Minio:
    return get_minio_client(get_config_value(CONFIG_EMAIL_ARCHIVE, CONFIG_EMAIL_ARCHIVE_S3_CONFIG))

class EmailArchiveMinio(EmailArchiveLocal):
    def email_exists_in_s3(self, sha256_hash: str) -> bool:
        bucket = get_config_value(CONFIG_EMAIL_ARCHIVE, CONFIG_EMAIL_ARCHIVE_S3_BUCKET)
        s3_client = _get_email_archive_minio_client()

        try:
            result = s3_client.stat_object(bucket_name=bucket, object_name=sha256_hash)
            return result is not None
        except S3Error as e:
            # if the object doesn't exist, stat_object raises an exception with code NoSuchKey
            if e.code == "NoSuchKey":
                logging.debug(f"email {sha256_hash} does not exist in s3: {e}")
                return False

            raise e

    def upload_to_s3(self, local_path: str, message_id: str, sha256_hash: str) -> bool:
        bucket = get_config_value(CONFIG_EMAIL_ARCHIVE, CONFIG_EMAIL_ARCHIVE_S3_BUCKET)
        metadata = { "message_id": message_id }
        logging.info(f"uploading email archive {sha256_hash} to {bucket} with metadata {metadata}")
        s3_client = _get_email_archive_minio_client()
        result = s3_client.fput_object(bucket_name=bucket, object_name=sha256_hash, file_path=local_path, user_metadata=metadata)
        logging.debug(f"uploaded email archive {sha256_hash} to {bucket}: {result}")
        return True

    def download_from_s3(self, target_path: str) -> str:
        """Downloads the email archive specified by the "local path" from S3 to a temporary file.
        Returns the path to the temporary file."""

        # make sure the target containing directory exists
        target_dir = os.path.dirname(target_path)
        os.makedirs(target_dir, exist_ok=True)

        # the only thing we need out of this is the sha256 hash embedded in the file name
        sha256_hash = _extract_sha256_from_file_name(target_path)

        # NOTE we want to keep the temporary file in the same directory as the target path
        # so then we we MOVE it to the target path it's guaranteed to be atomic
        # this is a cheap way to avoid concurrency issues
        fd, temp_path = tempfile.mkstemp(prefix=f'archive_{sha256_hash}.', suffix='.gz.e')
        os.close(fd)

        s3_client = _get_email_archive_minio_client()
        logging.info(f"downloading email archive {sha256_hash} to {temp_path}")
        s3_client.fget_object(
            get_config_value(CONFIG_EMAIL_ARCHIVE, CONFIG_EMAIL_ARCHIVE_S3_BUCKET),
            sha256_hash,
            temp_path)

        # move it to the target path
        os.rename(temp_path, target_path)
        return target_path

    def archive_email_file(self, file_path: str, message_id: str) -> str:
        """Stores the email in the archive system and returns the md5 hash of the archived email.
        If the email is already stored then nothing changes."""
        # archive it locally first
        sha256_hash = super().archive_email_file(file_path, message_id)

        # get the path to the file in the local archive
        local_path = self.get_archive_path_by_hash(sha256_hash)

        # have we already uploaded this file?
        if self.email_exists_in_s3(sha256_hash):
            logging.info(f"email {sha256_hash} already exists in S3")
            return sha256_hash

        # upload it to S3
        self.upload_to_s3(local_path, message_id, sha256_hash)

        # NOTE we're basically using the old (local) system as a cache for the S3 data
        #os.unlink(local_path)

        # return the S3 path
        return sha256_hash

    def iter_decrypt_email(self, target_path: str, chunk_size: Optional[int]=None):
        """Decrypt and iterate the contents of the target archived email."""
        # do we need to download it from S3? (it may already exist from a previous call)
        if not os.path.exists(target_path):
            self.download_from_s3(target_path)

        # and then iteratate on it
        yield from super().iter_decrypt_email(target_path, chunk_size)

    def archive_email_is_local(self, message_id: str) -> bool:
        """Returns True if the archived email is stored locally on this server."""
        # there is no locality for email archives in S3
        return True
