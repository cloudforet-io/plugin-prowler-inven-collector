import logging
import os
import json

from plugin.manager.profile_manager import ProfileManager

_LOGGER = logging.getLogger("spaceone")
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
