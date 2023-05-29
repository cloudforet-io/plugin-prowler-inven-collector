from spaceone.api.inventory.plugin import collector_pb2, collector_pb2_grpc
from spaceone.core.pygrpc import BaseAPI
from cloudforet.plugin.service.collector_service import CollectorService
from cloudforet.plugin.info.collector_info import PluginInfo, ResourceInfo
from cloudforet.plugin.info.common_info import EmptyInfo


class Collector(BaseAPI, collector_pb2_grpc.CollectorServicer):

    pb2 = collector_pb2
    pb2_grpc = collector_pb2_grpc

    def init(self, request, context):
        params, metadata = self.parse_request(request, context)

        with self.locator.get_service(CollectorService, metadata) as collector_service:
            return self.locator.get_info(PluginInfo, collector_service.init(params))

    def verify(self, request, context):
        params, metadata = self.parse_request(request, context)

        with self.locator.get_service(CollectorService, metadata) as collector_service:
            collector_service.verify(params)
            return self.locator.get_info(EmptyInfo)

    def collect(self, request, context):
        params, metadata = self.parse_request(request, context)

        with self.locator.get_service(CollectorService, metadata) as collector_service:
            response_stream = collector_service.collect(params)
            for resource_data in response_stream:
                yield self.locator.get_info(ResourceInfo, resource_data)
