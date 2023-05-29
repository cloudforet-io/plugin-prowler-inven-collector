import logging
from typing import Generator

from spaceone.core.service import *
from spaceone.core.error import *

from cloudforet.plugin.manager.aws_prowler_manager import AWSProwlerManager
from cloudforet.plugin.manager.collector_manager import CollectorManager

_LOGGER = logging.getLogger(__name__)


class CollectorService(BaseService):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @transaction
    @check_required(['options'])
    def init(self, params):
        """ init plugin by options

        Args:
            params (dict): {
                'options': 'dict',
                'domain_id': 'str'
            }

        Returns:
            plugin_data (dict)
        """

        options = params.get('options', {})

        collector_mgr: CollectorManager = self.locator.get_manager(CollectorManager)
        return collector_mgr.init_response(options)

    @transaction
    @check_required(['options', 'secret_data'])
    def verify(self, params):
        """ Verifying collector plugin

        Args:
            params (dict): {
                'options': 'dict',
                'schema': 'str',
                'secret_data': 'dict',
                'domain_id': 'str'
            }

        Returns:
            None
        """

        options = params['options']
        secret_data = params['secret_data']
        schema = params.get('schema')
        provider = options.get('provider', 'AWS')

        collector_mgr: AWSProwlerManager = self.locator.get_manager(AWSProwlerManager)
        collector_mgr.verify_client(options, secret_data, schema)

    @transaction
    @check_required(['options', 'secret_data'])
    def collect(self, params):
        """ Collect external data

        Args:
            params (dict): {
                'options': 'dict',
                'schema': 'str',
                'secret_data': 'dict',
                'domain_id': 'str'
            }

        Returns:
            generator of resource_data (dict)
        """

        options = params['options']
        secret_data = params['secret_data']
        schema = params.get('schema')

        collector_mgr: AWSProwlerManager = self.locator.get_manager(AWSProwlerManager)
        iterator = collector_mgr.collect(options, secret_data, schema)

        for resource_data in iterator:
            yield resource_data
