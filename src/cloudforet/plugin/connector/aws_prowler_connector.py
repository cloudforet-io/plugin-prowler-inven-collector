import os
import logging
import tempfile
import configparser
import command
from typing import List

from spaceone.core import utils
from spaceone.core.connector import BaseConnector
from cloudforet.plugin.error.custom import *
from cloudforet.plugin.model.prowler.collector import COMPLIANCE_TYPES

__all__ = ['AWSProwlerConnector']

_LOGGER = logging.getLogger(__name__)
_AWS_PROFILE_PATH = os.environ.get('AWS_SHARED_CREDENTIALS_FILE', os.path.expanduser('~/.aws/credentials'))
_AWS_PROFILE_DIR = _AWS_PROFILE_PATH.rsplit('/', 1)[0]


class AWSProfileManager:
    def __init__(self, credentials: dict):
        self._profile_name = utils.random_string()
        self._credentials = credentials

    @property
    def profile_name(self) -> str:
        return self._profile_name

    @property
    def credentials(self) -> dict:
        return self._credentials

    def __enter__(self) -> 'AWSProfileManager':
        self._add_aws_profile()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._remove_aws_profile()

    def _add_aws_profile(self):
        _LOGGER.debug(f'[_AWSProfileManager] add aws profile: {self._profile_name}')

        aws_profile = configparser.ConfigParser()

        if os.path.exists(_AWS_PROFILE_PATH) is False:
            self._create_aws_profile_file(aws_profile)

        aws_profile.read(_AWS_PROFILE_PATH)

        if self.profile_name in aws_profile.sections():
            self._remove_aws_profile(aws_profile)

        aws_profile.add_section(self.profile_name)

        for key, value in self._credentials.items():
            aws_profile.set(self.profile_name, key, value)

        with open(_AWS_PROFILE_PATH, 'w') as f:
            aws_profile.write(f)

    @staticmethod
    def _create_aws_profile_file(aws_profile: configparser.ConfigParser):
        os.makedirs(_AWS_PROFILE_DIR, exist_ok=True)
        aws_profile['default'] = {}
        with open(_AWS_PROFILE_PATH, 'w') as f:
            aws_profile.write(f)

    def _remove_aws_profile(self, aws_profile: configparser.ConfigParser = None):
        _LOGGER.debug(f'[_AWSProfileManager] remove aws profile: {self._profile_name}')

        if aws_profile is None:
            aws_profile = configparser.ConfigParser()
            aws_profile.read(_AWS_PROFILE_PATH)

        if self.profile_name in aws_profile.sections():
            aws_profile.remove_section(self.profile_name)

        with open(_AWS_PROFILE_PATH, 'w') as f:
            aws_profile.write(f)


class AWSProwlerConnector(BaseConnector):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._temp_dir = None

    def verify_client(self, options: dict, secret_data: dict, schema: str):
        self._check_secret_data(secret_data)

        with tempfile.TemporaryDirectory():
            with AWSProfileManager(secret_data) as aws_profile:
                cmd = self._command_prefix(aws_profile.profile_name)
                cmd += ['-l']
                _LOGGER.debug(f'[verify_client] command: {cmd}')
                command.run(cmd)

    def check(self, options: dict, secret_data: dict, schema: str):
        self._check_secret_data(secret_data)

        compliance_type = COMPLIANCE_TYPES['aws'].get(options['compliance_type'])

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                with AWSProfileManager(secret_data) as aws_profile:
                    cmd = self._command_prefix(aws_profile.profile_name)

                    cmd += ['-M', 'json', '-o', temp_dir, '-F', 'output', '-z']
                    cmd += ['--compliance', compliance_type]
                    cmd += ['-f', 'ap-northeast-2']

                    _LOGGER.debug(f'[check] command: {cmd}')
                    command.run(cmd)

                    output_json_file = os.path.join(temp_dir, 'output.json')
                    check_results = utils.load_json_from_file(output_json_file)
                    return check_results
        except Exception as e:
            raise ERROR_PROWLER_EXECUTION_FAILED(reason=e)

    @staticmethod
    def _check_secret_data(secret_data: dict):
        if 'aws_access_key_id' not in secret_data:
            raise ERROR_REQUIRED_PARAMETER(key='secret_data.aws_access_key_id')

        if 'aws_secret_access_key' not in secret_data:
            raise ERROR_REQUIRED_PARAMETER(key='secret_data.aws_secret_access_key')

    @staticmethod
    def _command_prefix(aws_profile_name: str) -> List[str]:
        return ['python3', '-m', 'prowler', 'aws', '-p', aws_profile_name, '-b']
