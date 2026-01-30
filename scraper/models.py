from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class JobEntry(BaseModel):
    title: str
    company: str
    location: Optional[str] = "Remote / Not Specified"
    description: Optional[str] = None
    application_url: str
    job_id: Optional[str] = None
    date_posted: Optional[str] = None
    employment_type: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        populate_by_name = True
