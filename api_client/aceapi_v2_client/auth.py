"""convenience helpers for authenticating against the ACE API v2

this module is hand-maintained and is NOT overwritten when the rest of the
package is regenerated from the openapi schema (see ../scripts/regenerate.sh).

the ACE API v2 authenticates machine clients with an api key sent in the custom
``x-ace-auth`` header. the generated ``AuthenticatedClient`` only knows how to
send ``Authorization: Bearer <token>``, so the helper below builds a plain
``Client`` with the api key header pre-populated instead.
"""

from .client import Client

# header name the ACE API v2 expects for machine-to-machine api key auth
API_KEY_HEADER = "x-ace-auth"


def authenticated_client(base_url, api_key, *, verify_ssl=True, **kwargs):
    """build a ``Client`` that authenticates with an ACE api key

    api keys are scoped: the effective permission of a key is the intersection of
    the key's own scope with its owner's permissions. a narrowly scoped key can
    therefore get ``403 {"detail": "Permission denied"}`` on endpoints its owner
    can otherwise reach.

    args:
        base_url: full base url including the ``/api/v2`` prefix, e.g.
            ``https://localhost:8443/api/v2``
        api_key: the ACE api key (sent in the ``x-ace-auth`` header)
        verify_ssl: verify the server tls certificate. set to ``False`` when
            talking to a development instance using a self-signed certificate.
        **kwargs: any other keyword argument accepted by ``Client`` (``timeout``,
            ``headers``, ``httpx_args``, etc). extra ``headers`` are merged with
            the api key header.

    returns:
        a configured ``Client`` ready to pass to the functions under
        ``aceapi_v2_client.api``.
    """
    headers = {API_KEY_HEADER: api_key, **kwargs.pop("headers", {})}
    return Client(base_url=base_url, headers=headers, verify_ssl=verify_ssl, **kwargs)
