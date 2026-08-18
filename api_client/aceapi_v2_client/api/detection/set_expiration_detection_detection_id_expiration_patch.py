from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.expiration_update import ExpirationUpdate
from ...models.http_validation_error import HTTPValidationError
from ...models.observable_detection_read import ObservableDetectionRead
from ...types import Response


def _get_kwargs(
    detection_id: int,
    *,
    body: ExpirationUpdate,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "patch",
        "url": "/detection/{detection_id}/expiration".format(
            detection_id=quote(str(detection_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | ObservableDetectionRead | None:
    if response.status_code == 200:
        response_200 = ObservableDetectionRead.from_dict(response.json())

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
) -> Response[HTTPValidationError | ObservableDetectionRead]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    detection_id: int,
    *,
    client: AuthenticatedClient,
    body: ExpirationUpdate,
) -> Response[HTTPValidationError | ObservableDetectionRead]:
    """Set Expiration

    Args:
        detection_id (int):
        body (ExpirationUpdate):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ObservableDetectionRead]
    """

    kwargs = _get_kwargs(
        detection_id=detection_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    detection_id: int,
    *,
    client: AuthenticatedClient,
    body: ExpirationUpdate,
) -> HTTPValidationError | ObservableDetectionRead | None:
    """Set Expiration

    Args:
        detection_id (int):
        body (ExpirationUpdate):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ObservableDetectionRead
    """

    return sync_detailed(
        detection_id=detection_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    detection_id: int,
    *,
    client: AuthenticatedClient,
    body: ExpirationUpdate,
) -> Response[HTTPValidationError | ObservableDetectionRead]:
    """Set Expiration

    Args:
        detection_id (int):
        body (ExpirationUpdate):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ObservableDetectionRead]
    """

    kwargs = _get_kwargs(
        detection_id=detection_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    detection_id: int,
    *,
    client: AuthenticatedClient,
    body: ExpirationUpdate,
) -> HTTPValidationError | ObservableDetectionRead | None:
    """Set Expiration

    Args:
        detection_id (int):
        body (ExpirationUpdate):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ObservableDetectionRead
    """

    return (
        await asyncio_detailed(
            detection_id=detection_id,
            client=client,
            body=body,
        )
    ).parsed
