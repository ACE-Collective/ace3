from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.api_key_read import ApiKeyRead
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/users/me/apikeys",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> list[ApiKeyRead] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = ApiKeyRead.from_dict(response_200_item_data)

            response_200.append(response_200_item)

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[list[ApiKeyRead]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[list[ApiKeyRead]]:
    """List My Api Keys

     List the *caller's own* API keys (metadata + scope only; no secret). The user id comes from
    the auth result, not the request, so there is no id to tamper with. Read-only: minting and
    revoking keys require ``user:write`` and go through the admin endpoints below.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[list[ApiKeyRead]]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> list[ApiKeyRead] | None:
    """List My Api Keys

     List the *caller's own* API keys (metadata + scope only; no secret). The user id comes from
    the auth result, not the request, so there is no id to tamper with. Read-only: minting and
    revoking keys require ``user:write`` and go through the admin endpoints below.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        list[ApiKeyRead]
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[list[ApiKeyRead]]:
    """List My Api Keys

     List the *caller's own* API keys (metadata + scope only; no secret). The user id comes from
    the auth result, not the request, so there is no id to tamper with. Read-only: minting and
    revoking keys require ``user:write`` and go through the admin endpoints below.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[list[ApiKeyRead]]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> list[ApiKeyRead] | None:
    """List My Api Keys

     List the *caller's own* API keys (metadata + scope only; no secret). The user id comes from
    the auth result, not the request, so there is no id to tamper with. Read-only: minting and
    revoking keys require ``user:write`` and go through the admin endpoints below.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        list[ApiKeyRead]
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
