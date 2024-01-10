import os
import logging
import tempfile
import subprocess
from typing import List

from spaceone.core import utils
from spaceone.core.connector import BaseConnector
from cloudforet.plugin.error.custom import *
from cloudforet.plugin.model.prowler.collector import COMPLIANCE_FRAMEWORKS

__all__ = ["AzureProwlerConnector"]

_LOGGER = logging.getLogger(__name__)
_AZURE_CREDENTIAL_ENVS = {
    "client_id": "AZURE_CLIENT_ID",
    "client_secret": "AZURE_CLIENT_SECRET",
    "tenant_id": "AZURE_TENANT_ID",
}


class AzureProwlerConnector(BaseConnector):
    provider = "azure"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._temp_dir = None

    def verify_client(self, options: dict, secret_data: dict, schema: str):
        self._check_secret_data(secret_data)

        with tempfile.TemporaryDirectory():
            cmd = self._command_prefix()
            cmd += ["-l"]
            _LOGGER.debug(f"[verify_client] command: {cmd}")

            sub_process_env = os.environ.copy()
            for key, value in _AZURE_CREDENTIAL_ENVS.items():
                sub_process_env[value] = secret_data[key]

            with subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env=sub_process_env,
            ) as sub_process:
                response, err_response = sub_process.communicate()

                if sub_process.returncode != 0:
                    raise ERROR_PROWLER_EXECUTION_FAILED(
                        reason=err_response.decode("utf-8")
                    )

    def check(self, options: dict, secret_data: dict, schema: str):
        self._check_secret_data(secret_data)
        regions = options.get("regions", [])

        compliance_framework = COMPLIANCE_FRAMEWORKS["azure"].get(
            options["compliance_framework"]
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            cmd = self._command_prefix()

            cmd += ["-M", "json", "-o", temp_dir, "-F", "output", "-z"]
            if compliance_framework:
                cmd += ["--compliance", compliance_framework]

            if regions:
                region_filter = ["-f"] + regions
                cmd += region_filter

            _LOGGER.debug(f"[check] command: {cmd}")

            sub_process_env = self.get_sub_process_env(secret_data)

            with subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env=sub_process_env,
            ) as sub_process:
                response, err_response = sub_process.communicate()

                if sub_process.returncode != 0:
                    raise ERROR_PROWLER_EXECUTION_FAILED(
                        reason=err_response.decode("utf-8")
                    )

                output_json_file = os.path.join(temp_dir, "output.json")
                check_results = utils.load_json_from_file(output_json_file)
                return check_results

    @staticmethod
    def get_sub_process_env(secret_data: dict):
        sub_process_env = os.environ.copy()
        for key, value in _AZURE_CREDENTIAL_ENVS.items():
            sub_process_env[value] = secret_data[key]

        return sub_process_env

    @staticmethod
    def _check_secret_data(secret_data: dict):
        if "tenant_id" not in secret_data:
            raise ERROR_REQUIRED_PARAMETER(key="secret_data.tenant_id")

        if "client_secret" not in secret_data:
            raise ERROR_REQUIRED_PARAMETER(key="secret_data.client_secret")

        if "client_id" not in secret_data:
            raise ERROR_REQUIRED_PARAMETER(key="secret_data.client_id")

    @staticmethod
    def _command_prefix(
        azure_profile_name: str = None, authentication_type: str = None
    ) -> List[str]:
        return ["python3", "-m", "prowler", "azure", "--sp-env-auth", "-b"]
