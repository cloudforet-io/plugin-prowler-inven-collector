from cloudforet.plugin.model.cloud_service_model import BaseCloudService

_METADATA = {
    'view': {
        'sub_data': {
            'layouts': [
                {
                    'type': 'item',
                    'name': 'Rule Details',
                    'options': {
                        'fields': [
                            {
                                'type': 'text',
                                'key': 'data.source.description',
                                'name': 'Description'
                            },
                            {
                                'type': 'text',
                                'key': 'data.name',
                                'name': 'Name'
                            },
                            {
                                'type': 'text',
                                'key': 'data.arn',
                                'name': 'ARN'
                            },
                            {
                                'type': 'text',
                                'key': 'data.source.owner_display',
                                'name': 'Type'
                            },
                            {
                                'type': 'text',
                                'key': 'data.source.trigger_type',
                                'name': 'Trigger Type'
                            },
                            {
                                'type': 'badge',
                                'key': 'data.scope.compliance_resource_types',
                                'name': 'Resource Types',
                                'options': {
                                    'delimiter': '<br>'
                                }
                            },
                        ]
                    }
                },
                {
                    'type': 'item',
                    'name': 'Conformance Pack',
                    'options': {
                        'fields': [
                            {
                                'type': 'text',
                                'key': 'data.conformance_pack.name',
                                'name': 'Name'
                            },
                            {
                                'type': 'text',
                                'key': 'data.conformance_pack.arn',
                                'name': 'ARN'
                            },
                            {
                                'type': 'text',
                                'key': 'data.conformance_pack.last_update_request_time',
                                'name': 'Last Update Time'
                            },
                        ]
                    }
                },
                {
                    'type': 'table',
                    'name': 'Resources',
                    'options': {
                        'fields': [
                            {
                                'type': 'text',
                                'key': 'resource_id',
                                'name': 'ID'
                            },
                            {
                                'type': 'text',
                                'key': 'resource_type',
                                'name': 'Type'
                            },
                            {
                                'type': 'enum',
                                'key': 'compliance_type',
                                'name': 'Compliance',
                                'options': {
                                    'COMPLIANT': {
                                        'name': 'Compliant',
                                        'type': 'badge',
                                        'options': {
                                            'background_color': 'indigo.500'
                                        }
                                    },
                                    'NON_COMPLIANT': {
                                        'name': 'Non Compliant',
                                        'type': 'badge',
                                        'options': {
                                            'background_color': 'coral.500'
                                        }
                                    },
                                    'INSUFFICIENT_DATA': {
                                        'name': 'Not Supported',
                                        'type': 'badge',
                                        'options': {
                                            'text_color': 'yellow.500'
                                        }
                                    }
                                }
                            },
                            {
                                'type': 'text',
                                'key': 'annotation',
                                'name': 'Annotation',
                                'options': {
                                    'default': '-'
                                }
                            },
                        ],
                        'root_path': 'data.resources'
                    }
                }
            ]
        }
    }
}


class CloudService(BaseCloudService):
    provider: str = 'aws'
    cloud_service_group: str = 'Compliance'
    cloud_service_type: str = 'CIS-AWS-1.4'
    metadata: dict = _METADATA
