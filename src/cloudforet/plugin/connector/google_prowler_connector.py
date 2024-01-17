import os
import json
import logging
import tempfile
import configparser
import subprocess
from typing import List

from spaceone.core import utils
from spaceone.core.connector import BaseConnector
from cloudforet.plugin.lib import ProfileManager
from cloudforet.plugin.error.custom import *
from cloudforet.plugin.model.prowler.collector import COMPLIANCE_FRAMEWORKS

__all__ = ["GoogleProwlerConnector"]
REQUIRED_SECRET_KEYS = [
    "type",
    "project_id",
    "private_key_id",
    "private_key",
    "client_email",
    "client_id",
    "auth_uri",
    "token_uri",
    "auth_provider_x509_cert_url",
    "client_x509_cert_url",
    "universe_domain",
]

_LOGGER = logging.getLogger(__name__)
_GOOGLE_CLOUD_PROFILE_PATH = os.environ.get(
    "GOOGLE_CLOUD_SHARED_CREDENTIALS_FILE",
    os.path.expanduser("~/.google_cloud/credentials"),
)
_GOOGLE_CLOUD_PROFILE_DIR = _GOOGLE_CLOUD_PROFILE_PATH.rsplit("/", 1)[0]


class GoogleProfileManager(ProfileManager):
    def _add_profile(self):
        _LOGGER.debug(
            f"[_GoogleProfileManager] add google profile: {self._profile_name}"
        )
        json_file_path = os.path.join(
            _GOOGLE_CLOUD_PROFILE_DIR, f"{self._profile_name}.json"
        )

        self.source_profile_path = json_file_path

        if os.path.exists(_GOOGLE_CLOUD_PROFILE_PATH) is False:
            self._create_profile_file()
        else:
            if not os.path.exists(json_file_path):
                self._create_profile_file()

    def _create_profile_file(self, **kwargs):
        os.makedirs(_GOOGLE_CLOUD_PROFILE_DIR, exist_ok=True)

        secret_data_json = json.dumps(self._credentials)
        with open(self.source_profile_path, "w") as f:
            f.write(secret_data_json)

    def _remove_profile(self, json_file_path=None):
        _LOGGER.debug(
            f"[_GoogleProfileManager] remove google cloud profile: {self._profile_name}"
        )

        if json_file_path:
            os.remove(json_file_path)


class GoogleProwlerConnector(BaseConnector):
    provider = "google_cloud"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._temp_dir = None

    def verify_client(self, options: dict, secret_data: dict, schema: str):
        self._check_secret_data(secret_data)

        with tempfile.TemporaryDirectory():
            with GoogleProfileManager(secret_data) as google_profile:
                cmd = self._command_prefix(google_profile.source_profile_path)
                cmd += ["-l"]
                _LOGGER.debug(f"[verify_client] command: {cmd}")
                response = subprocess.run(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
                )
                if response.returncode != 0:
                    raise ERROR_PROWLER_EXECUTION_FAILED(
                        reason=response.stderr.decode("utf-8")
                    )

    def check(self, options: dict, secret_data: dict, schema: str):
        self._check_secret_data(secret_data)

        compliance_framework = COMPLIANCE_FRAMEWORKS["google_cloud"].get(
            options["compliance_framework"]
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            with GoogleProfileManager(secret_data) as google_profile:
                cmd = self._command_prefix(google_profile.source_profile_path)

                cmd += ["-M", "json", "-o", temp_dir, "-F", "output", "-z"]
                cmd += ["--compliance", compliance_framework]

                _LOGGER.debug(f"[check] command: {cmd}")

                response = subprocess.run(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
                )
                if response.returncode != 0:
                    raise ERROR_PROWLER_EXECUTION_FAILED(
                        reason=response.stderr.decode("utf-8")
                    )

                output_json_file = os.path.join(temp_dir, "output.json")
                check_results = utils.load_json_from_file(output_json_file)
                return check_results

    @staticmethod
    def _check_secret_data(secret_data):
        missing_keys = [key for key in REQUIRED_SECRET_KEYS if key not in secret_data]
        if missing_keys:
            for key in missing_keys:
                raise ERROR_REQUIRED_PARAMETER(key=f"secret_data.{key}")

    @staticmethod
    def _command_prefix(source_profile_path) -> List[str]:
        return [
            "python3",
            "-m",
            "prowler",
            "gcp",
            "--credentials-file",
            source_profile_path,
            "-b",
        ]
