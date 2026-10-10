"""Wire schemas for the AI API's bulk export."""

from pydantic import BaseModel, Field

from aceapi_v2.alerts.schemas import AlertRow

MAX_ALERT_PAGE_SIZE = 1000
MAX_OBSERVABLE_IDS = 5000


class ExportDetection(BaseModel):
    """One detection point on an alert: which signature fired, and the node it sits on."""

    signature_uuid: str
    signature_version: str
    signature_family: str | None = None
    node_kind: str | None = Field(default=None, description="root, analysis or observable")
    node_type: str | None = Field(
        default=None, description="the type of the observable the detection sits on (or the observable of the "
                                  "analysis it sits on); null on the root")
    node_value_sha256: str | None = Field(
        default=None, description="that observable's sha256, as ExportObservable.sha256 carries it")


class ExportAlert(AlertRow):
    """An alert's database row plus what it maps to. Its observables are ids: fetch the ones you
    have not seen through POST /export/observables."""

    disposition_class: str | None = Field(
        default=None, description="tp, fp or null, from the server's disposition_classification")
    disposition_review: str = Field(description="UNREVIEWED, CORRECT or INCORRECT")
    incorrect_disposition: str | None = Field(
        default=None, description="the original disposition a reviewer found incorrect; `disposition` holds the correction")
    observable_ids: list[int] = Field(default_factory=list)
    detections: list[ExportDetection] = Field(default_factory=list)
    event_ids: list[int] = Field(default_factory=list)


class AlertExportPage(BaseModel):
    data: list[ExportAlert]
    next_cursor: str | None = Field(
        default=None,
        description="pass as ?cursor= with the same changed_since for the next page; null on the last page")


class ObservableExportRequest(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=MAX_OBSERVABLE_IDS)


class ExportObservable(BaseModel):
    id: int
    type: str
    sha256: str = Field(description="hex; for a file observable this is the content hash, which is also its value")
    value: str = Field(description="decoded as utf-8, ignoring undecodable bytes")


class ObservableExportPage(BaseModel):
    data: list[ExportObservable] = Field(description="the requested observables in id order; an unknown id is absent")
