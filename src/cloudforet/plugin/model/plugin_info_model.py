from typing import List
from pydantic import BaseModel
from enum import Enum


class ResourceType(str, Enum):
    cloud_service = 'inventory.CloudService'
    cloud_service_type = 'inventory.CloudServiceType'
    region = 'inventory.Region'
    error = 'inventory.ErrorResource'


class ScheduleType(str, Enum):
    hours = 'hours'
    interval = 'interval'


class Feature(str, Enum):
    garbage_collection = 'garbage_collection'


class PluginMetadata(BaseModel):
    options_schema: dict
    supported_features: List[Feature] = [Feature.garbage_collection]
    supported_resource_type: List[ResourceType]
    supported_schedules: List[ScheduleType] = [ScheduleType.hours]


class PluginInfo(BaseModel):
    metadata: PluginMetadata
