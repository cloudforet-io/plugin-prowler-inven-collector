import os
import logging
import re
import tempfile
import subprocess
from typing import List

from spaceone.core import utils
from spaceone.core.connector import BaseConnector
from plugin.conf.collector_conf import COMPLIANCE_FRAMEWORKS

__all__ = ["ProwlerConnector"]

from plugin.manager.aws_profile_manager import AWSProfileManager
from plugin.manager.google_profile_manager import GoogleProfileManager

_LOGGER = logging.getLogger("spaceone")
_AZURE_CREDENTIAL_ENVS = {
    "client_id": "AZURE_CLIENT_ID",
    "client_secret": "AZURE_CLIENT_SECRET",
    "tenant_id": "AZURE_TENANT_ID",
}
CURRENT_DIR = os.path.dirname(__file__)
METADATA_DIR = os.path.join(CURRENT_DIR, "../metadata/checks/")


class ProwlerConnector(BaseConnector):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._temp_dir = None

    def check(self, options: dict, secret_data: dict):
        provider = options.get("provider")
        regions = options.get("regions", [])
        checklist = options.get("check_list", [])
        compliance_framework = COMPLIANCE_FRAMEWORKS[provider].get(options["compliance_framework"])

        with tempfile.TemporaryDirectory() as temp_dir:
            err_message = None
            last_line = None
            if provider == "aws":
                with AWSProfileManager(secret_data) as aws_profile:
                    cmd = self._command_prefix(provider, aws_profile.profile_name)
                    cmd += self._get_collect_command(temp_dir, compliance_framework, regions, checklist)
                    _LOGGER.debug(f"[check] command: {cmd}")

                    response = subprocess.run(
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    )
                    if response.returncode != 0:
                        err_message = response.stderr.decode("utf-8")
                    last_line = response.stdout.decode("utf-8").strip().split('\n')[-1]
            elif provider == "azure":
                cmd = self._command_prefix(provider, None)
                cmd += self._get_collect_command(temp_dir, compliance_framework, regions, checklist)
                _LOGGER.debug(f"[check] command: {cmd}")

                sub_process_env = self.get_sub_process_env(secret_data)

                with subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env=sub_process_env,
                ) as sub_process:
                    response, err_response = sub_process.communicate()

                    if sub_process.returncode != 0:
                        err_message = err_response.decode("utf-8")
                    last_line = response.decode("utf-8").strip().split('\n')[-1]
            elif provider == "google_cloud":
                with GoogleProfileManager(secret_data) as google_profile:
                    cmd = self._command_prefix(provider, google_profile.source_profile_path)
                    cmd += self._get_collect_command(temp_dir, compliance_framework, regions, checklist)
                    _LOGGER.debug(f"[check] command: {cmd}")

                    response = subprocess.run(
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    )
                    if response.returncode != 0:
                        err_message = response.stderr.decode("utf-8")
                    last_line = response.stdout.decode("utf-8").strip().split('\n')[-1]
            last_message = re.sub(r'\x1b\[[0-9;]*m','',last_line)

            if 'there are no findings' in last_message.lower():
                return [], last_message
            else:
                output_json_file = os.path.join(temp_dir, "output.ocsf.json")
                if os.path.exists(output_json_file):
                    check_results = utils.load_json_from_file(output_json_file)
                    return check_results, err_message
                else:
                    return [], err_message


    @staticmethod
    def _command_prefix(provider: str, profile_name: str) -> List[str]:
        cmd = ["python3", "-m", "prowler", ]

        if provider == "aws":
            cmd += ["aws", "-p", profile_name, "-b"]
        elif provider == "azure":
            cmd += ["azure", "--sp-env-auth", "-b", "--azure-region", "AzureCloud"]
        elif provider == "google_cloud":
            cmd += ["gcp", "--credentials-file", profile_name, "-b"]

        return cmd

    @staticmethod
    def _get_collect_command(temp_dir: str, compliance_framework: str, regions, checklist: List[str]) -> List[str]:
        cmd = ["-M", "json-ocsf", "-o", temp_dir, "-F", "output", "-z"]

        if checklist:
            checklist_filter = ["--check"] + checklist
            cmd += checklist_filter
        else:
            cmd += ["--compliance", compliance_framework]

        if regions:
            region_filter = ["-f"] + regions
            cmd += region_filter

        _LOGGER.debug(f"[check] command: {cmd}")

        return cmd

    @staticmethod
    def get_sub_process_env(secret_data: dict):
        sub_process_env = os.environ.copy()
        for key, value in _AZURE_CREDENTIAL_ENVS.items():
            sub_process_env[value] = secret_data[key]

        return sub_process_env
