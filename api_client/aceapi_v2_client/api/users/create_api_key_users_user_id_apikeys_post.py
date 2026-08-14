from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.api_key_create import ApiKeyCreate
from ...models.api_key_created import ApiKeyCreated
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    user_id: int,
    *,
    body: ApiKeyCreate,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/users/{user_id}/apikeys".format(
            user_id=quote(str(user_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ApiKeyCreated | HTTPValidationError | None:
    if response.status_code == 201:
        response_201 = ApiKeyCreated.from_dict(response.json())

        return response_201

    if response.status_code == 422:
        response_422 = HTTPValidationError.from_dict(response.json())

        return response_422

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ApiKeyCreated | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    user_id: int,
    *,
    client: AuthenticatedClient,
    body: ApiKeyCreate,
) -> Response[ApiKeyCreated | HTTPValidationError]:
    """Create Api Key

     Mint a new API key for a user. The plaintext is returned exactly once and is never
    recoverable afterward. Exactly one of ``inherit`` or a non-empty ``scope`` must be provided.

    Args:
        user_id (int):
        body (ApiKeyCreate): Request to mint a key. Exactly one of `inherit` or a non-empty
            `scope` must be set --
            the server rejects both-or-neither, so a restricted key can never silently get full scope.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ApiKeyCreated | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        user_id=user_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    user_id: int,
    *,
    client: AuthenticatedClient,
    body: ApiKeyCreate,
) -> ApiKeyCreated | HTTPValidationError | None:
    """Create Api Key

     Mint a new API key for a user. The plaintext is returned exactly once and is never
    recoverable afterward. Exactly one of ``inherit`` or a non-empty ``scope`` must be provided.

    Args:
        user_id (int):
        body (ApiKeyCreate): Request to mint a key. Exactly one of `inherit` or a non-empty
            `scope` must be set --
            the server rejects both-or-neither, so a restricted key can never silently get full scope.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ApiKeyCreated | HTTPValidationError
    """

    return sync_detailed(
        user_id=user_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    user_id: int,
    *,
    client: AuthenticatedClient,
    body: ApiKeyCreate,
) -> Response[ApiKeyCreated | HTTPValidationError]:
    """Create Api Key

     Mint a new API key for a user. The plaintext is returned exactly once and is never
    recoverable afterward. Exactly one of ``inherit`` or a non-empty ``scope`` must be provided.

    Args:
        user_id (int):
        body (ApiKeyCreate): Request to mint a key. Exactly one of `inherit` or a non-empty
            `scope` must be set --
            the server rejects both-or-neither, so a restricted key can never silently get full scope.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ApiKeyCreated | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        user_id=user_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    user_id: int,
    *,
    client: AuthenticatedClient,
    body: ApiKeyCreate,
) -> ApiKeyCreated | HTTPValidationError | None:
    """Create Api Key

     Mint a new API key for a user. The plaintext is returned exactly once and is never
    recoverable afterward. Exactly one of ``inherit`` or a non-empty ``scope`` must be provided.

    Args:
        user_id (int):
        body (ApiKeyCreate): Request to mint a key. Exactly one of `inherit` or a non-empty
            `scope` must be set --
            the server rejects both-or-neither, so a restricted key can never silently get full scope.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ApiKeyCreated | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            user_id=user_id,
            client=client,
            body=body,
        )
    ).parsed
