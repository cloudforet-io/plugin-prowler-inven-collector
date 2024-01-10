import logging
from typing import Generator

from spaceone.core.error import *
from spaceone.core.manager import BaseManager
from cloudforet.plugin.model.plugin_info_model import ResourceType
from cloudforet.plugin.model.resource_info_model import ResourceInfo, State
from cloudforet.plugin.model.prowler.collector import (
    AWSPluginInfo,
    AzurePluginInfo,
    GoogleCloudPluginInfo,
)
from cloudforet.plugin.connector.aws_prowler_connector import AWSProwlerConnector
from cloudforet.plugin.connector.azure_prowler_connector import AzureProwlerConnector

_LOGGER = logging.getLogger(__name__)


class CollectorManager(BaseManager):
    provider = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.provider = None
        self.cloud_service_group = None
        self.cloud_service_type = None
        self.region_name = None
        self.aws_prowler_connector: AWSProwlerConnector = self.locator.get_connector(
            AWSProwlerConnector
        )
        self.azure_prowler_connector: AzureProwlerConnector = (
            self.locator.get_connector(AzureProwlerConnector)
        )

    @staticmethod
    def init_response(options: dict) -> dict:
        provider = options.get("provider")
        if provider == "aws":
            response = AWSPluginInfo()
            return response.dict()
        elif provider == "azure":
            response = AzurePluginInfo()
            return response.dict()
        elif provider == "google_cloud":
            response = GoogleCloudPluginInfo()
            return response.dict()
        else:
            raise ERROR_INVALID_PARAMETER(
                key="options.provider", reason="Not supported provider."
            )

    def verify_client(self, options: dict, secret_data: dict, schema: str) -> None:
        provider = options.get("provider")
        if provider == "aws":
            self.aws_prowler_connector.verify_client(options, secret_data, schema)
        elif provider == "azure":
            self.azure_prowler_connector.verify_client(options, secret_data, schema)
        elif provider == "google_cloud":
            pass
        else:
            raise ERROR_INVALID_PARAMETER(
                key="options.provider", reason="Not supported provider."
            )

    def collect(
        self, options: dict, secret_data: dict, schema: str
    ) -> Generator[dict, None, None]:
        raise NotImplementedError("Method not implemented!")

    def make_response(
        self,
        resource_data: dict,
        match_rules: dict,
        resource_type: str = "inventory.CloudService",
    ) -> dict:
        return self.validate_response(
            {
                "state": State.success,
                "resource_type": resource_type,
                "match_rules": match_rules,
                "resource": resource_data,
            }
        )

    def error_response(
        self, error: Exception, resource_type: str = "inventory.CloudService"
    ) -> dict:
        if not isinstance(error, ERROR_BASE):
            error = ERROR_UNKNOWN(message=error)

        _LOGGER.error(
            f"[error_response] ({self.region_name}) {error.error_code}: {error.message}",
            exc_info=True,
        )
        return self.validate_response(
            {
                "state": State.failre,
                "message": error.message,
                "resource_type": ResourceType.error,
                "resource": {
                    "provider": self.provider,
                    "cloud_service_group": self.cloud_service_group,
                    "cloud_service_type": self.cloud_service_type,
                    "resource_type": resource_type,
                },
            }
        )

    @classmethod
    def get_collector_manager_by_provider(cls, provider):
        for sub_cls in cls.__subclasses__():
            if sub_cls.provider == provider:
                return sub_cls()
        raise ERROR_INVALID_PARAMETER(key="provider", reason="Not supported provider")

    @staticmethod
    def validate_response(resource_data):
        response = ResourceInfo(**resource_data)
        return response.dict()
