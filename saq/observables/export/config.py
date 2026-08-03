from typing import Optional

from pydantic import BaseModel, Field


class ObservableExportConfig(BaseModel):
    """The base configuration of an ``observable_export_<name>:`` block."""

    name: str = Field(..., description="Unique identifier for the export target.")
    python_module: str = Field(..., description="The Python module that contains the export class.")
    python_class: str = Field(..., description="The name of the export class inside the module.")
    enabled: bool = Field(default=True, description="Controls whether the export target is enabled or disabled.")
    description: Optional[str] = Field(default=None, description="A brief description of the export target.")
