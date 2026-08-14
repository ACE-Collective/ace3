from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.detection_page import DetectionPage
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    search: None | str | Unset = UNSET,
    observable_type: None | str | Unset = UNSET,
    page: int | Unset = 1,
    page_size: int | Unset = 50,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_search: None | str | Unset
    if isinstance(search, Unset):
        json_search = UNSET
    else:
        json_search = search
    params["search"] = json_search

    json_observable_type: None | str | Unset
    if isinstance(observable_type, Unset):
        json_observable_type = UNSET
    else:
        json_observable_type = observable_type
    params["observable_type"] = json_observable_type

    params["page"] = page

    params["page_size"] = page_size

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/detection/",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> DetectionPage | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = DetectionPage.from_dict(response.json())

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
) -> Response[DetectionPage | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    search: None | str | Unset = UNSET,
    observable_type: None | str | Unset = UNSET,
    page: int | Unset = 1,
    page_size: int | Unset = 50,
) -> Response[DetectionPage | HTTPValidationError]:
    """List Detections

    Args:
        search (None | str | Unset):
        observable_type (None | str | Unset):
        page (int | Unset):  Default: 1.
        page_size (int | Unset):  Default: 50.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DetectionPage | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        search=search,
        observable_type=observable_type,
        page=page,
        page_size=page_size,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    search: None | str | Unset = UNSET,
    observable_type: None | str | Unset = UNSET,
    page: int | Unset = 1,
    page_size: int | Unset = 50,
) -> DetectionPage | HTTPValidationError | None:
    """List Detections

    Args:
        search (None | str | Unset):
        observable_type (None | str | Unset):
        page (int | Unset):  Default: 1.
        page_size (int | Unset):  Default: 50.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DetectionPage | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        search=search,
        observable_type=observable_type,
        page=page,
        page_size=page_size,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    search: None | str | Unset = UNSET,
    observable_type: None | str | Unset = UNSET,
    page: int | Unset = 1,
    page_size: int | Unset = 50,
) -> Response[DetectionPage | HTTPValidationError]:
    """List Detections

    Args:
        search (None | str | Unset):
        observable_type (None | str | Unset):
        page (int | Unset):  Default: 1.
        page_size (int | Unset):  Default: 50.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DetectionPage | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        search=search,
        observable_type=observable_type,
        page=page,
        page_size=page_size,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    search: None | str | Unset = UNSET,
    observable_type: None | str | Unset = UNSET,
    page: int | Unset = 1,
    page_size: int | Unset = 50,
) -> DetectionPage | HTTPValidationError | None:
    """List Detections

    Args:
        search (None | str | Unset):
        observable_type (None | str | Unset):
        page (int | Unset):  Default: 1.
        page_size (int | Unset):  Default: 50.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DetectionPage | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            search=search,
            observable_type=observable_type,
            page=page,
            page_size=page_size,
        )
    ).parsed
