from typing import List
from pydantic import BaseModel
from enum import Enum


class UpgradeMode(str, Enum):
    auto = 'AUTO'
    manual = ' MANUAL'


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
    supported_features: List[Feature] = [Feature.garbage_collection]
    supported_resource_type: List[ResourceType]
    supported_schedules: List[ScheduleType] = [ScheduleType.hours]
    upgrade_mode: UpgradeMode = UpgradeMode.auto


class PluginInfo(BaseModel):
    metadata: PluginMetadata
