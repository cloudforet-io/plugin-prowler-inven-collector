import logging
import abc

from spaceone.core import utils

_LOGGER = logging.getLogger("spaceone")


class ProfileManager:
    def __init__(self, credentials: dict):
        self._profile_name = utils.random_string()
        self._source_profile_name = None
        self._source_profile_path = None
        self._credentials = credentials

    @property
    def profile_name(self) -> str:
        return self._profile_name

    @property
    def source_profile_name(self) -> str:
        return self._source_profile_name

    @source_profile_name.setter
    def source_profile_name(self, value: str):
        self._source_profile_name = value

    @property
    def source_profile_path(self) -> str:
        return self._source_profile_path

    @source_profile_path.setter
    def source_profile_path(self, value: str):
        self._source_profile_path = value

    @property
    def credentials(self) -> dict:
        return self._credentials

    def __enter__(self) -> "ProfileManager":
        self._add_profile()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._remove_profile()

    @abc.abstractmethod
    def _add_profile(self):
        raise NotImplemented("Please implement _add_profile method")

    @abc.abstractmethod
    def _create_profile_file(self, profile):
        raise NotImplemented("Please implement _create_profile_file method")

    @abc.abstractmethod
    def _remove_profile(self, profile=None):
        raise NotImplemented("Please implement _remove_profile method")
