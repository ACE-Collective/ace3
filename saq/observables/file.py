import hashlib
import io
import logging
import os
from subprocess import PIPE, Popen
from typing import Optional, Union
from saq.analysis.observable import Observable
from saq.analysis.presenter.observable_presenter import ObservablePresenter, register_observable_presenter
from saq.analysis.serialize.observable_serializer import KEY_VALUE
from saq.configuration.config import get_config
from saq.constants import DIRECTIVE_VIEW_IN_BROWSER, EVENT_RELATIONSHIP_ADDED, F_FILE, F_FILE_LOCATION, F_FILE_NAME, F_FILE_PATH, F_MD5, F_SHA1, F_SHA256, FILE_SUBDIR, R_IS_HASH_OF, parse_file_location
from saq.gui import ObservableActionCollectFile, ObservableActionDownloadFile, ObservableActionDownloadFileAsZip, ObservableActionFileRender, ObservableActionSeparator, ObservableActionUploadToVt, ObservableActionViewAsHex, ObservableActionViewAsHtml, ObservableActionViewAsText, ObservableActionViewInBrowser, ObservableActionViewInVt
from saq.observables.base import CaselessObservable, ObservableValueError
from saq.observables.generator import register_observable_type
from saq.util.hashing import is_sha256_hex

KEY_MD5_HASH = "md5_hash"
KEY_SHA1_HASH = "sha1_hash"
KEY_SHA256_HASH = "sha256_hash"
KEY_MIME_TYPE = "mime_type"
KEY_SIZE = "size"
KEY_FILE_PATH = "file_path"

class FileObservable(Observable):
    def __init__(self, value=None, file_path=None, *args, **kwargs):
        assert file_path

        # The 'value' of a FileObservable is its sha256 hash.
        # It is passed as the first argument to the parent constructor.
        super().__init__(F_FILE, value, *args, **kwargs)

        self._file_path = file_path
        self._md5_hash = None
        self._sha1_hash = None
        self._size = None

        self._mime_type = None

        self._scaled_width = None
        self._scaled_height = None

        self._sha256_hash = self.value

        # some directives are inherited by children
        self.add_event_listener(EVENT_RELATIONSHIP_ADDED, self.handle_relationship_added)

    def __eq__(self, other):
        if not isinstance(other, FileObservable):
            return False

        # two of these are equal if they have the same content AND the same metadata
        return self.value == other.value and self.file_path == other.file_path

    def __hash__(self):
        # the value of a FileObservable is the sha256 hash of the file, so we can just hash that
        return hash(self.value)

    def __str__(self) -> str:
        return self.file_path

    def __repr__(self) -> str:
        return self.file_path

    # XXX should not ever be set, should be computed instead
    # loader should load _value
    @Observable.value.setter
    def value(self, new_value):
        assert isinstance(new_value, str)
        assert is_sha256_hex(new_value)
        
        self._value = new_value

    @property
    def tag_mapping_type(self):
        return F_SHA256

    @property
    def tag_mapping_value(self):
        return self.sha256_hash

    @property
    def tag_mapping_md5_hex(self):
        if self.sha256_hash is None:
            return None

        md5_hasher = hashlib.md5()
        md5_hasher.update(self.sha256_hash.encode('utf8', errors='ignore'))
        return md5_hasher.hexdigest()

    @property
    def json(self):
        result = Observable.json.fget(self)
        result.update({
            KEY_FILE_PATH: self.file_path,
            KEY_MD5_HASH: self.md5_hash,
            KEY_SHA1_HASH: self.sha1_hash,
            KEY_SHA256_HASH: self.sha256_hash,
            KEY_MIME_TYPE: self._mime_type,
            KEY_SIZE: self._size,
        })
        return result

    @json.setter
    def json(self, value):
        assert isinstance(value, dict)
        Observable.json.fset(self, value)

        if KEY_FILE_PATH in value:
            self._file_path = value[KEY_FILE_PATH]
        if KEY_MD5_HASH in value:
            self._md5_hash = value[KEY_MD5_HASH]
        if KEY_SHA1_HASH in value:
            self._sha1_hash = value[KEY_SHA1_HASH]
        if KEY_SHA256_HASH in value:
            self._sha256_hash = value[KEY_SHA256_HASH]
        if KEY_MIME_TYPE in value:
            self._mime_type = value[KEY_MIME_TYPE]
        if KEY_SIZE in value:
            self._size = value[KEY_SIZE]

    @staticmethod
    def from_json(value: dict) -> "FileObservable":
        result = FileObservable(value=value[KEY_VALUE], file_path=value[KEY_FILE_PATH])
        result.json = value
        return result

    @property
    def file_name(self) -> str:
        """Returns the name of the file regardless of path."""
        return os.path.basename(self.file_path)

    @property
    def file_path(self) -> str:
        """Returns the path to the file relative to the file storage directory for the containing RootAnalysis."""
        return self._file_path

    @property
    def full_path(self) -> str:
        """Returns the full path to the file."""
        return os.path.join(self.file_manager.storage_dir, FILE_SUBDIR, self.file_path)

    @property
    def md5_hash(self):
        self.compute_hashes()
        return self._md5_hash

    @property
    def sha1_hash(self):
        self.compute_hashes()
        return self._sha1_hash

    @property
    def sha256_hash(self):
        self.compute_hashes()
        return self._sha256_hash

    @property
    def size(self):
        """Returns the size of the file in bytes, or None if the size cannot be computed."""
        if self._size is not None:
            return self._size

        try:
            self._size = os.path.getsize(self.full_path)
        except Exception as e:
            logging.warning(f"unable to determine size of {self.full_path}: {e}")
            self._size = None

        return self._size

    def compute_hashes(self):
        """Computes the md5, sha1 and sha256 hashes of the file and stores them as properties."""

        if self._md5_hash is not None and self._sha1_hash is not None and self._sha256_hash is not None:
            return True

        md5_hasher = hashlib.md5()
        sha1_hasher = hashlib.sha1()
        sha256_hasher = hashlib.sha256()
    
        try:
            with open(self.path, 'rb') as fp:
                while True:
                    data = fp.read(io.DEFAULT_BUFFER_SIZE)
                    if data == b'':
                        break

                    md5_hasher.update(data)
                    sha1_hasher.update(data)
                    sha256_hasher.update(data)

        except Exception as e:
            # this will happen if a F_FILE observable refers to a file that no longer (or never did) exists
            logging.debug(f"unable to compute hashes of {self.file_path}: {e}")
            return False
        
        self._md5_hash = md5_hasher.hexdigest()
        self._sha1_hash = sha1_hasher.hexdigest()
        self._sha256_hash = sha256_hasher.hexdigest()
        return True

    @property
    def display_preview(self) -> Optional[bytes]:
        try:
            with open(self.full_path, 'rb') as fp:
                return fp.read(get_config().gui.file_preview_bytes).decode('utf8', errors='replace')
        except FileNotFoundError:
            # This usually happens when someone tries to view a file in an archived alert
            logging.warning(f"file does not exist for display_preview: {self.full_path}")
            return None

    @property
    def display_value(self) -> str:
        return self.file_path

    @property
    def jinja_template_path(self) -> str:
        return "analysis/file_observable.html"

    @property
    def mime_type(self) -> Optional[str]:
        if self._mime_type:
            return self._mime_type

        p = Popen(['file', '-b', '--mime-type', '-L', self.path], stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()

        if len(stderr) > 0:
            logging.warning("file command returned error output for {}".format(self.path))

        self._mime_type = stdout.decode(errors='ignore').strip()
        return self._mime_type

    @property
    def path(self) -> str:
        return self.full_path

    @property
    def ext(self) -> Optional[str]:
        """Returns the file extension of this file in lower case, or None if it doesn't have one."""
        if '.' not in self.full_path:
            return None

        try:
            return os.path.basename(self.full_path).split('.')[-1].lower()
        except Exception as e:
            logging.error(f"unable to get file extension of {self.full_path}: {e}")
            return None

    @property
    def exists(self) -> bool:
        try:
            return os.path.exists(self.full_path)
        except Exception as e:
            logging.warning(f"unable to stat path: {self.full_path}: {e}")
            return False

    @property
    def human_readable_size(self) -> str:
        from math import log2

        if self.size is None:
            return ""

        _suffixes = ["bytes", "K", "M", "G", "T", "E", "Z"]

        # determine binary order in steps of size 10 
        # (coerce to int, // still returns a float)
        order = int(log2(self.size) / 10) if self.size else 0
        # format file size
        # (.4g results in rounded numbers for exact matches and max 3 decimals, 
        # should never resort to exponent values)
        return "{:.4g} {}".format(self.size / (1 << (order * 10)), _suffixes[order])

    @property
    def jinja_available_actions(self):
        result = []
        if self.exists:
            if self.has_directive("view_as_html"):
                result.append(ObservableActionViewAsHtml())
                result.append(ObservableActionSeparator())
            elif self.has_directive(DIRECTIVE_VIEW_IN_BROWSER):
                result.append(ObservableActionViewInBrowser())
                result.append(ObservableActionSeparator())
            result.append(ObservableActionDownloadFile())
            result.append(ObservableActionDownloadFileAsZip())
            result.append(ObservableActionSeparator())
            result.append(ObservableActionViewAsHex())
            result.append(ObservableActionViewAsText())
            result.append(ObservableActionSeparator())
            result.append(ObservableActionUploadToVt())
            result.append(ObservableActionViewInVt())
            
            result.append(ObservableActionSeparator())
            result.append(ObservableActionFileRender())

            result.append(ObservableActionSeparator())
        result.extend(super().jinja_available_actions)
        return result

    @property
    def is_image(self) -> bool:
        """Returns True if the file command thinks this file is an image."""
        if self.mime_type is None:
            return False

        return self.mime_type.startswith("image")

    def compute_scaled_dimensions(self):
        if self._scaled_width is not None and self._scaled_height is not None:
            return

        from PIL import Image
        try:
            with Image.open(self.full_path) as image:
                width, height = image.size
        except Exception as e:
            logging.warning("unable to parse image {}: {}".format(self.path, e))
            return

        w_ratio = 1.0
        h_ratio = 1.0

        #if width > 640:
            #w_ratio = 640.0 / float(width)

        #if height > 480:
            #h_ratio = 480.0 / float(height)

        if width > 320:
            w_ratio = 320.0 / float(width)

        if height > 240:
            h_ratio = 240.0 / float(height)

        ratio = w_ratio if w_ratio > h_ratio else h_ratio
        self._scaled_width = int(width * ratio)
        self._scaled_height = int(height * ratio)

    @property
    def scaled_width(self):
        if not self.is_image:
            return None

        if self._scaled_width:
            return self._scaled_width

        self.compute_scaled_dimensions()
        return self._scaled_width

    @property
    def scaled_height(self):
        if not self.is_image:
            return None

        if self._scaled_height:
            return self._scaled_height

        self.compute_scaled_dimensions()
        return self._scaled_height

    def handle_relationship_added(self, source, event, target, relationship=None):
        pass


class FileObservablePresenter(ObservablePresenter):
    """Presenter for FileObservable."""

    @property
    def template_path(self) -> str:
        return "analysis/file_observable.html"

    @property
    def available_actions(self) -> list:
        from saq.gui.observable_actions.file import (
            ObservableActionDownloadFileAsZip,
            ObservableActionViewAsHex,
            ObservableActionViewAsText,
            ObservableActionViewInBrowser,
            ObservableActionFileRender,
        )
        from saq.gui import ObservableActionSeparator

        result = [
            ObservableActionDownloadFileAsZip(),
            ObservableActionViewAsHex(),
            ObservableActionViewAsText(),
            ObservableActionViewInBrowser(),
            ObservableActionFileRender(),
            ObservableActionSeparator(),
        ]
        result.extend(super().available_actions)
        return result


register_observable_presenter(FileObservable, FileObservablePresenter)


class FilePathObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_FILE_PATH, *args, **kwargs)

    @property
    def jinja_available_actions(self):
        result = [ ]
        result.extend(super().jinja_available_actions)
        return result

class FileNameObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_FILE_NAME, *args, **kwargs)

    @property
    def jinja_available_actions(self):
        result = [ ]
        result.extend(super().jinja_available_actions)
        return result

class FileLocationObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_FILE_LOCATION, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value
        self._hostname, self._full_path = parse_file_location(self.value)

    @property
    def hostname(self):
        return self._hostname

    @property
    def full_path(self):
        return self._full_path

    @property
    def jinja_available_actions(self):
        result = [ ObservableActionCollectFile(), ObservableActionSeparator() ]
        result.extend(super().jinja_available_actions)
        return result

    @property
    def jinja_template_path(self):
        return "analysis/file_location_observable.html"


class FileLocationObservablePresenter(ObservablePresenter):
    """Presenter for FileLocationObservable."""

    @property
    def template_path(self) -> str:
        return "analysis/file_location_observable.html"

    @property
    def available_actions(self) -> list:
        from saq.gui.observable_actions.file import ObservableActionCollectFile
        from saq.gui import ObservableActionSeparator

        result = [ObservableActionCollectFile(), ObservableActionSeparator()]
        result.extend(super().available_actions)
        return result


register_observable_presenter(FileLocationObservable, FileLocationObservablePresenter)


class MD5Observable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_MD5, *args, **kwargs)

    @CaselessObservable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()
        if self.value.count('0') == len(self.value):
            raise ObservableValueError(f"invalid MD5 {self.value}")

    @property
    def related_file(self) -> Union[FileObservable, None]:
        related = self.get_relationship_by_type(R_IS_HASH_OF)
        return related.target if related else None

    @property
    def jinja_available_actions(self):
        result = [ ]
        result.extend(super().jinja_available_actions)
        return result


class SHA1Observable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_SHA1, *args, **kwargs)

    @CaselessObservable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()
        if self.value.count('0') == len(self.value):
            raise ObservableValueError(f"invalid SHA1 {self.value}")

    @property
    def related_file(self) -> Union[FileObservable, None]:
        related = self.get_relationship_by_type(R_IS_HASH_OF)
        return related.target if related else None

    @property
    def jinja_available_actions(self):
        result = [ ]
        result.extend(super().jinja_available_actions)
        return result


class SHA1ObservablePresenter(ObservablePresenter):
    """Presenter for SHA1Observable."""

    @property
    def template_path(self) -> str:
        return "analysis/default_observable.html"


register_observable_presenter(SHA1Observable, SHA1ObservablePresenter)


class SHA256Observable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_SHA256, *args, **kwargs)

    @CaselessObservable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()
        if self.value.count('0') == len(self.value):
            raise ObservableValueError(f"invalid SHA256 {self.value}")

    @property
    def related_file(self) -> Union[FileObservable, None]:
        related = self.get_relationship_by_type(R_IS_HASH_OF)
        return related.target if related else None

    @property
    def jinja_template_path(self):
        return "analysis/sha256_observable.html"

    @property
    def jinja_available_actions(self):
        result = [ ]
        result.extend(super().jinja_available_actions)
        return result


class SHA256ObservablePresenter(ObservablePresenter):
    """Presenter for SHA256Observable."""

    @property
    def template_path(self) -> str:
        return "analysis/sha256_observable.html"


register_observable_presenter(SHA256Observable, SHA256ObservablePresenter)

register_observable_type(F_FILE, FileObservable)
register_observable_type(F_FILE_PATH, FilePathObservable)
register_observable_type(F_FILE_NAME, FileNameObservable)
register_observable_type(F_FILE_LOCATION, FileLocationObservable)
register_observable_type(F_MD5, MD5Observable)
register_observable_type(F_SHA1, SHA1Observable)
register_observable_type(F_SHA256, SHA256Observable)