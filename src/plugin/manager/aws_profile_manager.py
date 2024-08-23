import logging
import os
import configparser

from spaceone.core import utils
from plugin.manager.profile_manager import ProfileManager

_LOGGER = logging.getLogger("spaceone")
_AWS_PROFILE_PATH = os.environ.get(
    "AWS_SHARED_CREDENTIALS_FILE", os.path.expanduser("~/.aws/credentials")
)
_AWS_PROFILE_DIR = _AWS_PROFILE_PATH.rsplit("/", 1)[0]


class AWSProfileManager(ProfileManager):
    def _add_profile(self):
        _LOGGER.debug(f"[_AWSProfileManager] add aws profile: {self._profile_name}")

        aws_profile = configparser.ConfigParser()

        if os.path.exists(_AWS_PROFILE_PATH) is False:
            self._create_profile_file(aws_profile)

        aws_profile.read(_AWS_PROFILE_PATH)

        if self.profile_name in aws_profile.sections():
            self._remove_profile(aws_profile)

        aws_profile.add_section(self.profile_name)

        if "role_arn" in self._credentials:
            self.source_profile_name = utils.random_string()
            aws_profile.add_section(self.source_profile_name)
            aws_profile.set(
                self.source_profile_name,
                "aws_access_key_id",
                self._credentials["aws_access_key_id"],
            )
            aws_profile.set(
                self.source_profile_name,
                "aws_secret_access_key",
                self._credentials["aws_secret_access_key"],
            )

            aws_profile.set(
                self.profile_name, "role_arn", self._credentials["role_arn"]
            )
            aws_profile.set(
                self.profile_name, "source_profile", self.source_profile_name
            )

            if "external_id" in self._credentials:
                aws_profile.set(
                    self.profile_name, "external_id", self._credentials["external_id"]
                )

        else:
            aws_profile.set(
                self.profile_name,
                "aws_access_key_id",
                self._credentials["aws_access_key_id"],
            )
            aws_profile.set(
                self.profile_name,
                "aws_secret_access_key",
                self._credentials["aws_secret_access_key"],
            )

        with open(_AWS_PROFILE_PATH, "w") as f:
            aws_profile.write(f)

    def _create_profile_file(self, aws_profile: configparser.ConfigParser):
        os.makedirs(_AWS_PROFILE_DIR, exist_ok=True)
        aws_profile["default"] = {}
        with open(_AWS_PROFILE_PATH, "w") as f:
            aws_profile.write(f)

    def _remove_profile(self, aws_profile: configparser.ConfigParser = None):
        _LOGGER.debug(f"[_AWSProfileManager] remove aws profile: {self._profile_name}")

        if aws_profile is None:
            aws_profile = configparser.ConfigParser()
            aws_profile.read(_AWS_PROFILE_PATH)

        if self.profile_name in aws_profile.sections():
            aws_profile.remove_section(self.profile_name)

        if (
                self.source_profile_name
                and self.source_profile_name in aws_profile.sections()
        ):
            aws_profile.remove_section(self.source_profile_name)

        with open(_AWS_PROFILE_PATH, "w") as f:
            aws_profile.write(f)
