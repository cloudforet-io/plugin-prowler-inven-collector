import copy
import os
import abc
import logging
from typing import Generator

from spaceone.core.error import *
from spaceone.core.manager import BaseManager
from spaceone.core import utils
from spaceone.inventory.plugin.collector.lib import *
from plugin.conf.global_conf import ICON_URL_PREFIX

_LOGGER = logging.getLogger("spaceone")
CURRENT_DIR = os.path.dirname(__file__)
METRIC_DIR = os.path.join(CURRENT_DIR, "../metrics/")

__all__ = ["ResourceManager"]


class ResourceManager(BaseManager):
    provider = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.name = None
        self.provider = None
        self.cloud_service_group = "Prowler"
        self.cloud_service_type = None
        self.service_code = None
        self.is_primary = False
        self.icon = "prowler.svg"
        self.labels = ["Security", "Compliance", "CSPM"]
        self.metadata_path = "metadata/prowler.yaml"
        self.prowler_connector = None

    def __repr__(self):
        return f"{self.__class__.__name__}"

    def collect_resources(self, options: dict, secret_data: dict, schema: str) -> Generator[dict, None, None]:
        try:
            self.provider = options.get("provider")
            self.cloud_service_type = options["compliance_framework"]

            if self.provider == "aws":
                self.is_primary = True
                self.name = f"AWS {self.cloud_service_type}"
            elif self.provider == "azure":
                self.name = f"Azure {self.cloud_service_type}"
            elif self.provider == "google_cloud":
                self.name = f"Google Cloud {self.cloud_service_type}"
            else:
                raise ERROR_INVALID_PARAMETER(
                    key="options.provider", reason="Not supported provider."
                )

            _LOGGER.debug(f"[{self.__repr__()}] Collect cloud service type: "
                          f"{self.cloud_service_group} > {self.provider}_{self.cloud_service_type}")
            yield self.get_cloud_service_type()

            _LOGGER.debug(f"[{self.__repr__()}] Collect metrics: "
                          f"{self.cloud_service_group} > {self.provider}_{self.cloud_service_type}")
            yield from self.collect_metrics()

            _LOGGER.debug(f"[{self.__repr__()}] Collect cloud services: "
                          f"{self.cloud_service_group} > {self.provider}_{self.cloud_service_type}")
            response_iterator = self.collect_cloud_services(options, secret_data, schema)
            for response in response_iterator:
                try:
                    yield make_response(
                        resource_type="inventory.CloudService",
                        cloud_service=response,
                        match_keys=[
                            [
                                "reference.resource_id",
                                "provider",
                                "cloud_service_type",
                                "cloud_service_group",
                                "account",
                            ]
                        ],
                    )
                except Exception as e:
                    _LOGGER.error(f"[{self.__repr__()}] Error: {str(e)}", exc_info=True)
                    yield make_error_response(
                        error=e,
                        provider=self.provider,
                        cloud_service_group=self.cloud_service_group,
                        cloud_service_type=self.cloud_service_type,
                    )

        except Exception as e:
            _LOGGER.error(f"[{self.__repr__()}] Error: {str(e)}", exc_info=True)
            yield make_error_response(
                error=e,
                provider=self.provider,
                cloud_service_group=self.cloud_service_group,
                cloud_service_type=self.cloud_service_type,
            )

    @abc.abstractmethod
    def collect_cloud_services(self, options: dict, secret_data: dict, schema: str) -> Generator[dict, None, None]:
        raise ERROR_NOT_IMPLEMENTED()

    def get_cloud_service_type(self) -> dict:
        cloud_service_type = make_cloud_service_type(
            name=self.name,
            group=self.cloud_service_group,
            provider=self.provider,
            metadata_path=self.metadata_path,
            is_primary=self.is_primary,
            is_major=self.is_primary,
            service_code=self.service_code,
            tags={"spaceone:icon": f"{ICON_URL_PREFIX}/{self.icon}"},
            labels=self.labels,
        )

        return make_response(
            resource_type="inventory.CloudServiceType",
            cloud_service_type=cloud_service_type,
            match_keys=[["name", "group", "provider"]],
        )

    def collect_metrics(self) -> dict:
        for dirname in os.listdir(os.path.join(METRIC_DIR, self.cloud_service_group)):
            for filename in os.listdir(os.path.join(METRIC_DIR, self.cloud_service_group, dirname)):
                if filename.endswith(".yaml"):
                    file_path = os.path.join(METRIC_DIR, self.cloud_service_group, dirname, filename)
                    info = utils.load_yaml_from_file(file_path)
                    if filename == "namespace.yaml":
                        yield make_response(
                            namespace=info,
                            match_keys=[],
                            resource_type="inventory.Namespace",
                        )
                    else:
                        yield make_response(
                            metric=info,
                            match_keys=[],
                            resource_type="inventory.Metric",
                        )
