from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.user_details_users_details_get_response_user_details_users_details_get import (
    UserDetailsUsersDetailsGetResponseUserDetailsUsersDetailsGet,
)
from ...types import UNSET, Response


def _get_kwargs(
    *,
    user_ids: list[int],
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_user_ids = user_ids

    params["user_ids"] = json_user_ids

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/users/details",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | UserDetailsUsersDetailsGetResponseUserDetailsUsersDetailsGet
    | None
):
    if response.status_code == 200:
        response_200 = (
            UserDetailsUsersDetailsGetResponseUserDetailsUsersDetailsGet.from_dict(
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
    HTTPValidationError | UserDetailsUsersDetailsGetResponseUserDetailsUsersDetailsGet
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    user_ids: list[int],
) -> Response[
    HTTPValidationError | UserDetailsUsersDetailsGetResponseUserDetailsUsersDetailsGet
]:
    """User Details

    Args:
        user_ids (list[int]):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UserDetailsUsersDetailsGetResponseUserDetailsUsersDetailsGet]
    """

    kwargs = _get_kwargs(
        user_ids=user_ids,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    user_ids: list[int],
) -> (
    HTTPValidationError
    | UserDetailsUsersDetailsGetResponseUserDetailsUsersDetailsGet
    | None
):
    """User Details

    Args:
        user_ids (list[int]):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UserDetailsUsersDetailsGetResponseUserDetailsUsersDetailsGet
    """

    return sync_detailed(
        client=client,
        user_ids=user_ids,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    user_ids: list[int],
) -> Response[
    HTTPValidationError | UserDetailsUsersDetailsGetResponseUserDetailsUsersDetailsGet
]:
    """User Details

    Args:
        user_ids (list[int]):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UserDetailsUsersDetailsGetResponseUserDetailsUsersDetailsGet]
    """

    kwargs = _get_kwargs(
        user_ids=user_ids,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    user_ids: list[int],
) -> (
    HTTPValidationError
    | UserDetailsUsersDetailsGetResponseUserDetailsUsersDetailsGet
    | None
):
    """User Details

    Args:
        user_ids (list[int]):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UserDetailsUsersDetailsGetResponseUserDetailsUsersDetailsGet
    """

    return (
        await asyncio_detailed(
            client=client,
            user_ids=user_ids,
        )
    ).parsed
