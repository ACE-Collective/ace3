from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.delete_secret_secrets_key_delete_response_delete_secret_secrets_key_delete import (
    DeleteSecretSecretsKeyDeleteResponseDeleteSecretSecretsKeyDelete,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    key: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/secrets/{key}".format(
            key=quote(str(key), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    DeleteSecretSecretsKeyDeleteResponseDeleteSecretSecretsKeyDelete
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = (
            DeleteSecretSecretsKeyDeleteResponseDeleteSecretSecretsKeyDelete.from_dict(
                response.json()
            )
        )

        return response_200

    if response.status_code == 422:
        response_422 = HTTPValidationError.from_dict(response.json())

        return response_422

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    DeleteSecretSecretsKeyDeleteResponseDeleteSecretSecretsKeyDelete
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    key: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    DeleteSecretSecretsKeyDeleteResponseDeleteSecretSecretsKeyDelete
    | HTTPValidationError
]:
    """Delete Secret

    Args:
        key (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteSecretSecretsKeyDeleteResponseDeleteSecretSecretsKeyDelete | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        key=key,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    key: str,
    *,
    client: AuthenticatedClient,
) -> (
    DeleteSecretSecretsKeyDeleteResponseDeleteSecretSecretsKeyDelete
    | HTTPValidationError
    | None
):
    """Delete Secret

    Args:
        key (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteSecretSecretsKeyDeleteResponseDeleteSecretSecretsKeyDelete | HTTPValidationError
    """

    return sync_detailed(
        key=key,
        client=client,
    ).parsed


async def asyncio_detailed(
    key: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    DeleteSecretSecretsKeyDeleteResponseDeleteSecretSecretsKeyDelete
    | HTTPValidationError
]:
    """Delete Secret

    Args:
        key (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteSecretSecretsKeyDeleteResponseDeleteSecretSecretsKeyDelete | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        key=key,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    key: str,
    *,
    client: AuthenticatedClient,
) -> (
    DeleteSecretSecretsKeyDeleteResponseDeleteSecretSecretsKeyDelete
    | HTTPValidationError
    | None
):
    """Delete Secret

    Args:
        key (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteSecretSecretsKeyDeleteResponseDeleteSecretSecretsKeyDelete | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            key=key,
            client=client,
        )
    ).parsed
