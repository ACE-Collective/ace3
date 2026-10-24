import os

from saq.cli.cli_main import get_cli_subparsers
from saq.configuration.config import get_config
from saq.js_deobfuscator import maintain_files


js_deobfuscator_parser = get_cli_subparsers().add_parser("js-deobfuscator", help="Manage the js-deobfuscator service.")
js_deobfuscator_sp = js_deobfuscator_parser.add_subparsers(dest="js_deobfuscator_cmd")

def cli_maintain_files(args) -> int:
    max_file_age_days = args.max_file_age_days
    if max_file_age_days is None:
        max_file_age_days = get_config().js_deobfuscator.max_file_age_days
    result = maintain_files(max_file_age_days)
    print(result)
    return os.EX_OK

js_deobfuscator_maintain_parser = js_deobfuscator_sp.add_parser("maintain-files",
    help="Delete js-deobfuscator input/output files older than the configured age.")
js_deobfuscator_maintain_parser.add_argument("--max-file-age-days", type=int, default=None,
    help="Delete js-deobfuscator input/output directories older than this many days "
         "(default: js_deobfuscator.max_file_age_days from config).")
js_deobfuscator_maintain_parser.set_defaults(func=cli_maintain_files)
