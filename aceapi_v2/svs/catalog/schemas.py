"""Wire schemas for the Atomic Red Team test catalog (/svs/tests)."""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class CatalogTest(BaseModel):
    """An Atomic Red Team test, by its auto_generated_guid."""

    guid: str = Field(description="the test's auto_generated_guid, lower case")
    repository: str = Field(description="the name of the git_repo_* section it is read from")
    technique: str = Field(description="the ATT&CK technique of its atomic file, e.g. T1059.001")
    technique_name: Optional[str] = None
    name: str
    platforms: list[str] = Field(description="its supported_platforms")
    executor: Optional[str] = Field(default=None, description="command_prompt, powershell, sh, bash or manual")
    path: str = Field(description="its atomic file, relative to the repository")
    commit: str = Field(description="the repository commit this version of the test was first read from")
    content_hash: str = Field(description="sha256 of the test's entry; it changes exactly when the test does")
    first_seen_at: datetime
    removed_at: Optional[datetime] = Field(default=None, description="when the test disappeared from its repository; it keeps its runs")
    updated_at: datetime


class CatalogTestDetail(CatalogTest):
    description: Optional[str] = None
    test: dict[str, Any] = Field(description="the test's entry in its atomic file: executor (commands), input_arguments, dependencies")


class CatalogTestPage(BaseModel):
    data: list[CatalogTest]
    next_cursor: Optional[str] = None


CATALOG_TEST_CSV_FIELDS = tuple(CatalogTest.model_fields)
