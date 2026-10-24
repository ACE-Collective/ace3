# vim: sw=4:ts=4:et:cc=120
#
# various utility functions
#

from saq.util.filesystem import create_directory, remove_directory, abs_path, is_nt_path, extract_windows_filepaths, atomic_open, map_mimetype_to_file_ext
from saq.util.hashing import sha256, sha256_str
from saq.util.networking import is_ipv4, add_netmask, is_subdomain, is_url, iterate_fqdn_parts, fully_qualified
from saq.util.parsing import json_parse
from saq.util.time import create_timedelta, parse_event_time, local_time, format_iso8601
from saq.util.ui import human_readable_size, create_histogram_string, get_tag_css_class
from saq.util.url import fang, find_all_url_domains
from saq.util.uuid import validate_uuid, is_uuid, storage_dir_from_uuid, workload_storage_dir
