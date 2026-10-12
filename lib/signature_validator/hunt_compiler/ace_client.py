"""Connecting to ACE from a signature repository's CI: the connection arguments every command takes,
their environment defaults, and requests made with them (an API key, and optionally a custom CA
bundle and a PEM or PKCS#12 client certificate)."""

import argparse
import os
from dataclasses import dataclass
from typing import Any, Optional

import requests

try:
    from requests_pkcs12 import request as pkcs12_request
    PKCS12_AVAILABLE = True
except ImportError:
    PKCS12_AVAILABLE = False


def add_connection_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-r",
        "--remote-host",
        type=str,
        help="The remote host to connect to",
        default=os.environ.get("ACE_API_HOST", "aceatu.com:443"),
    )
    parser.add_argument(
        "-u",
        "--ui-host",
        type=str,
        help="The UI host to link to",
        default=os.environ.get("ACE_UI_HOST", "aceatu.com:443"),
    )
    parser.add_argument(
        "-k",
        "--api-key",
        type=str,
        help="The api key to use",
        default=os.environ.get("ACE_API_KEY", None),
    )
    parser.add_argument(
        "-V",
        "--disable-ssl-verification",
        action="store_true",
        help="Whether to disable the ssl certificate verification",
        default=False,
    )
    parser.add_argument(
        "--ca-bundle",
        type=str,
        help="Path to a custom root CA bundle file for SSL certificate verification",
        default=os.environ.get("ACE_CA_BUNDLE", None),
    )
    parser.add_argument(
        "--client-cert",
        type=str,
        help="Path to a client SSL certificate file (can be combined cert+key or specify --client-key separately)",
        default=os.environ.get("ACE_CLIENT_CERT", None),
    )
    parser.add_argument(
        "--client-key",
        type=str,
        help="Path to a client SSL certificate key file (required if --client-cert is not a combined file)",
        default=os.environ.get("ACE_CLIENT_KEY", None),
    )
    parser.add_argument(
        "--client-p12",
        type=str,
        help="Path to a PKCS#12 (.p12/.pfx) client certificate file (alternative to --client-cert)",
        default=os.environ.get("ACE_CLIENT_P12", None),
    )
    parser.add_argument(
        "--client-p12-password",
        type=str,
        help="Password for the PKCS#12 file (can also be set via ACE_CLIENT_P12_PASSWORD env var)",
        default=os.environ.get("ACE_CLIENT_P12_PASSWORD", None),
    )


def validate_connection_arguments(args: argparse.Namespace) -> None:
    """Raises ValueError for connection arguments that cannot work."""
    if args.api_key is None:
        raise ValueError(
            "The API key is not set! Please set the ACE_API_KEY environment variable."
        )

    if args.client_cert and args.client_p12:
        raise ValueError(
            "Cannot specify both --client-cert and --client-p12. Use one or the other."
        )

    if args.client_p12 and not PKCS12_AVAILABLE:
        raise ValueError(
            "requests-pkcs12 library is not installed. Install it with: pip install requests-pkcs12"
        )


@dataclass(frozen=True)
class Connection:
    remote_host: str
    api_key: str
    disable_ssl_verification: bool = False
    ca_bundle: Optional[str] = None
    client_cert: Optional[str] = None
    client_key: Optional[str] = None
    client_p12: Optional[str] = None
    client_p12_password: Optional[str] = None

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "Connection":
        return cls(
            remote_host=args.remote_host,
            api_key=args.api_key,
            disable_ssl_verification=args.disable_ssl_verification,
            ca_bundle=args.ca_bundle,
            client_cert=args.client_cert,
            client_key=args.client_key,
            client_p12=args.client_p12,
            client_p12_password=args.client_p12_password,
        )

    def url(self, path: str) -> str:
        return f"https://{self.remote_host}{path}"

    def request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Sends the request to path on the remote host with the API key. The response is returned
        whatever its status."""
        if self.disable_ssl_verification:
            verify_setting = False
        elif self.ca_bundle:
            verify_setting = self.ca_bundle
        else:
            verify_setting = True

        kwargs = {"headers": {"x-ace-auth": self.api_key}, "verify": verify_setting, **kwargs}
        if self.client_p12:
            return pkcs12_request(
                method, self.url(path),
                pkcs12_filename=self.client_p12,
                pkcs12_password=self.client_p12_password,
                **kwargs,
            )

        cert_setting = None
        if self.client_cert:
            cert_setting = (self.client_cert, self.client_key) if self.client_key else self.client_cert

        return requests.request(method, self.url(path), cert=cert_setting, **kwargs)
