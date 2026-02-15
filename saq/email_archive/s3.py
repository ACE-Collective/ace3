import logging
import os
import tempfile
from typing import Optional

try:
    import botocore.exceptions  # noqa
    HAS_BOTOCORE = True
except ImportError:
    HAS_BOTOCORE = False

from saq.configuration.config import get_config
from saq.email_archive.local import EmailArchiveLocal
from saq.storage.s3 import get_s3_client


def _extract_sha256_from_file_name(file_path: str) -> str:
    """Given a local email archive file path, extract the sha256 hash from the file name."""
    # see get_archive_path_by_hash
    # file name should be sha256_hash.lower().gz.e
    return os.path.basename(file_path).split('.')[0]

class EmailArchiveS3(EmailArchiveLocal):
    def email_exists_in_s3(self, sha256_hash: str) -> bool:
        bucket = get_config().email_archive.s3_bucket
        s3_client = get_s3_client()

        try:
            s3_client.head_object(Bucket=bucket, Key=sha256_hash)
            return True
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "404":
                logging.debug("email %s does not exist in s3: %s", sha256_hash, e)
                return False

            raise e

    def upload_to_s3(self, local_path: str, message_id: str, sha256_hash: str) -> bool:
        bucket = get_config().email_archive.s3_bucket
        metadata = { "message_id": message_id }
        logging.info("uploading email archive %s to %s with metadata %s", sha256_hash, bucket, metadata)
        s3_client = get_s3_client()
        s3_client.upload_file(local_path, bucket, sha256_hash, ExtraArgs={"Metadata": metadata})
        logging.debug("uploaded email archive %s to %s", sha256_hash, bucket)
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
        fd, temp_path = tempfile.mkstemp(prefix=f'archive_{sha256_hash}.', suffix='.gz.e', dir=os.path.dirname(target_path))
        os.close(fd)

        s3_client = get_s3_client()
        logging.info("downloading email archive %s to %s", sha256_hash, temp_path)
        s3_client.download_file(
            get_config().email_archive.s3_bucket,
            sha256_hash,
            temp_path)

        # once it's downloaded we move it to the target path
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
            logging.info("email %s already exists in s3", sha256_hash)
            return sha256_hash

        # upload it to S3
        self.upload_to_s3(local_path, message_id, sha256_hash)

        # NOTE we're basically using the old (local) system as a cache for the S3 data

        # return the S3 path
        return sha256_hash

    def iter_decrypt_email(self, target_path: str, chunk_size: Optional[int]=None):
        """Decrypt and iterate the contents of the target archived email."""
        # do we need to download it from S3? (it may already exist from a previous call)
        if not os.path.exists(target_path):
            self.download_from_s3(target_path)

        # and then iterate on it
        yield from super().iter_decrypt_email(target_path, chunk_size)

    def archive_email_is_local(self, message_id: str) -> bool:
        """Returns True if the archived email is stored locally on this server."""
        # there is no locality for email archives in S3
        return True
