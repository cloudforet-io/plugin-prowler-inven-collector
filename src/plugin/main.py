import logging
import time
from typing import Generator

from spaceone.inventory.plugin.collector.lib.server import CollectorPluginServer
from spaceone.core.error import ERROR_INVALID_PARAMETER, ERROR_REQUIRED_PARAMETER
from plugin.conf.global_conf import *
from plugin.conf.collector_conf import *
from .manager.prowler_manager import ProwlerManager

app = CollectorPluginServer()

_LOGGER = logging.getLogger("spaceone")


@app.route("Collector.init")
def collector_init(params: dict) -> dict:
    options = params["options"]
    provider = options.get("provider", "aws")

    return _create_init_metadata(provider)


@app.route("Collector.collect")
def collector_collect(params: dict) -> Generator[dict, None, None]:
    options = params["options"]
    provider = params["options"].get("provider")
    secret_data = params["secret_data"]
    schema = params.get("schema")

    _check_secret_data(provider, secret_data)

    start_time = time.time()
    _LOGGER.debug(
        f"[collector_collect] Start Collecting Cloud Resources (provider: {provider})"
    )
    yield from ProwlerManager().collect_resources(options, secret_data, schema)

    _LOGGER.debug(
        f"[collector_collect] Finished Collecting Cloud Resources "
        f"(provider: {provider}, duration: {time.time() - start_time:.2f}s)"
    )


def _create_init_metadata(provider: str) -> dict:
    init_metadata = {
        "metadata": {
            "supported_resource_type": SUPPORTED_RESOURCE_TYPE,
            "supported_schedules": SUPPORTED_SCHEDULES,
            "supported_features": SUPPORTED_FEATURES,
            "options_schema": {
                "required": ["provider", "compliance_framework"],
                "order": ["provider", "compliance_framework", "regions"],
                "type": "object",
                "properties": {
                    "provider": {
                        "title": "Provider",
                        "type": "string",
                        "default": provider,
                        "disabled": True,
                    },
                    "compliance_framework": {
                        "title": "Compliance Framework",
                        "type": "string",
                        "enum": list(COMPLIANCE_FRAMEWORKS[provider].keys()),
                        "default": "CIS-2.0",
                    },
                    "regions": {
                        "title": "Region Filter",
                        "type": "array",
                        "items": {"enum": {}},
                    },
                    # 'services': {
                    #     'title': 'Service',
                    #     'type': 'array',
                    #     'items': {
                    #         'enum': list(SERVICES[provider].keys())
                    #     }
                    # },
                    # 'severity': {
                    #     'title': 'Severity',
                    #     'type': 'array',
                    #     'items': {
                    #         'enum': list(SEVERITIES.keys())
                    #     }
                    # }
                },
            },
        }
    }

    if provider == "aws":
        init_metadata["metadata"]["options_schema"]["properties"]["regions"]["items"]["enum"] = REGIONS[provider]
        init_metadata["metadata"]["options_schema"]["properties"]["compliance_framework"]["default"] = "CIS-3.0"
    elif provider == "azure":
        del init_metadata["metadata"]["options_schema"]["properties"]["regions"]
        init_metadata["metadata"]["options_schema"]["properties"]["compliance_framework"]["default"] = "CIS-2.1"
    elif provider == "google_cloud":
        del init_metadata["metadata"]["options_schema"]["properties"]["regions"]
        init_metadata["metadata"]["options_schema"]["properties"]["compliance_framework"]["default"] = "CIS-2.0"
    else:
        raise ERROR_INVALID_PARAMETER(
            key="options.provider", reason="Not supported provider."
        )

    return init_metadata


def _check_secret_data(provider: str, secret_data: dict) -> None:
    match provider:
        case "aws" | "azure" | "google_cloud":
            missing_keys = [key for key in REQUIRED_SECRET_KEYS[provider] if key not in secret_data]
            if missing_keys:
                for key in missing_keys:
                    raise ERROR_REQUIRED_PARAMETER(key=f"secret_data.{key}")
        case _:
            raise ERROR_INVALID_PARAMETER(
                key="options.provider", reason="Not supported provider."
            )
