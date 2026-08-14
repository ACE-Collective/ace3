from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.delete_groups_users_groups_delete_post_response_delete_groups_users_groups_delete_post import (
    DeleteGroupsUsersGroupsDeletePostResponseDeleteGroupsUsersGroupsDeletePost,
)
from ...models.group_delete import GroupDelete
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    *,
    body: GroupDelete,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/users/groups/delete",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    DeleteGroupsUsersGroupsDeletePostResponseDeleteGroupsUsersGroupsDeletePost
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = DeleteGroupsUsersGroupsDeletePostResponseDeleteGroupsUsersGroupsDeletePost.from_dict(
            response.json()
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
    DeleteGroupsUsersGroupsDeletePostResponseDeleteGroupsUsersGroupsDeletePost
    | HTTPValidationError
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
    body: GroupDelete,
) -> Response[
    DeleteGroupsUsersGroupsDeletePostResponseDeleteGroupsUsersGroupsDeletePost
    | HTTPValidationError
]:
    """Delete Groups

    Args:
        body (GroupDelete):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteGroupsUsersGroupsDeletePostResponseDeleteGroupsUsersGroupsDeletePost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: GroupDelete,
) -> (
    DeleteGroupsUsersGroupsDeletePostResponseDeleteGroupsUsersGroupsDeletePost
    | HTTPValidationError
    | None
):
    """Delete Groups

    Args:
        body (GroupDelete):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteGroupsUsersGroupsDeletePostResponseDeleteGroupsUsersGroupsDeletePost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: GroupDelete,
) -> Response[
    DeleteGroupsUsersGroupsDeletePostResponseDeleteGroupsUsersGroupsDeletePost
    | HTTPValidationError
]:
    """Delete Groups

    Args:
        body (GroupDelete):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteGroupsUsersGroupsDeletePostResponseDeleteGroupsUsersGroupsDeletePost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: GroupDelete,
) -> (
    DeleteGroupsUsersGroupsDeletePostResponseDeleteGroupsUsersGroupsDeletePost
    | HTTPValidationError
    | None
):
    """Delete Groups

    Args:
        body (GroupDelete):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteGroupsUsersGroupsDeletePostResponseDeleteGroupsUsersGroupsDeletePost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
