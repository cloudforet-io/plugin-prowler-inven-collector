from typing import List
from cloudforet.plugin.model.cloud_service_type_model import BaseCloudServiceType

_METADATA = {
    'view': {
        'search': [
            {
                'key': 'data.description',
                'name': 'Description'
            },
            {
                'key': 'data.requirement_id',
                'name': 'Requirement ID'
            },
            {
                'key': 'data.status',
                'name': 'Status'
            },
            {
                'key': 'data.display.score',
                'name': 'Score (%)',
                'data_type': 'float'
            },
            {
                'key': 'data.service',
                'name': 'Service'
            }
        ],
        'table': {
            'layout': {
                'name': '',
                'type': 'query-search-table',
                'options': {
                    'fields': [
                        {
                            'type': 'text',
                            'key': 'data.requirement_id',
                            'name': 'Requirement ID'
                        },
                        {
                            'type': 'enum',
                            'name': 'Status',
                            'key': 'data.status',
                            'options': {
                                'FAIL': {
                                    'type': 'badge',
                                    'options': {
                                        'background_color': 'coral.500'
                                    }
                                },
                                'PASS': {
                                    'type': 'badge',
                                    'options': {
                                        'background_color': 'indigo.500'
                                    }
                                }
                            }
                        },
                        {
                            'type': 'text',
                            'key': 'data.display.checks',
                            'name': 'Checks',
                            'options': {
                                'sortable': False
                            }
                        },
                        {
                            'type': 'text',
                            'key': 'data.display.findings',
                            'name': 'Findings',
                            'options': {
                                'sortable': False,
                                'is_optional': True
                            }
                        },
                        {
                            'type': 'text',
                            'key': 'data.display.score',
                            'name': 'Score',
                            'options': {
                                'postfix': '%',
                                'is_optional': True
                            }
                        },
                        {
                            'type': 'integer',
                            'key': 'data.failed_resource_count',
                            'name': 'Failed Resources'
                        },
                        {
                            'type': 'text',
                            'key': 'data.service',
                            'name': 'Service'
                        }
                    ]
                }
            }
        },
        'widget': [
            {
                'name': 'Total Count',
                'type': 'summary',
                'options': {
                    'value_options': {
                        'key': 'value',
                        'options': {
                            'default': 0
                        }
                    }
                },
                'query': {
                    'aggregate': [
                        {
                            'count': {
                                'name': 'value'
                            }
                        }
                    ],
                    'filter': []
                }
            },
            {
                'name': 'Failed Count',
                'type': 'summary',
                'options': {
                    'value_options': {
                        'key': 'value',
                        'options': {
                            'default': 0
                        }
                    }
                },
                'query': {
                    'aggregate': [
                        {
                            'count': {
                                'name': 'value'
                            }
                        }
                    ],
                    'filter': [
                        {'key': 'data.status', 'value': 'FAIL', 'operator': 'eq'}
                    ]
                }
            },
            {
                'name': 'Compliance Score (%)',
                'type': 'summary',
                'options': {
                    'value_options': {
                        'key': 'value',
                        'options': {
                            'default': 0,
                            'postfix': '%'
                        }
                    }
                },
                'query': {
                    'aggregate': [
                        {
                            'average': {
                                'key': 'data.display.score',
                                'name': 'value'
                            }
                        }
                    ],
                    'filter': [
                        {'key': 'data.status', 'value': 'FAIL', 'operator': 'eq'}
                    ]
                }
            },
        ],
        'sub_data': {
            'layouts': [
                {
                    'type': 'table',
                    'name': 'Checks',
                    'options': {
                        'fields': [
                            {
                                'type': 'text',
                                'key': 'check_title',
                                'name': 'Check Title'
                            },
                            {
                                'type': 'enum',
                                'name': 'Status',
                                'key': 'status',
                                'options': {
                                    'FAIL': {
                                        'type': 'badge',
                                        'options': {
                                            'background_color': 'coral.500'
                                        }
                                    },
                                    'PASS': {
                                        'type': 'badge',
                                        'options': {
                                            'background_color': 'indigo.500'
                                        }
                                    }
                                }
                            },
                            {
                                'type': 'text',
                                'key': 'display.findings',
                                'name': 'Findings',
                                'options': {
                                    'sortable': False
                                }
                            },
                            {
                                'type': 'text',
                                'key': 'service',
                                'name': 'Service'
                            },
                            {
                                'type': 'enum',
                                'key': 'severity',
                                'name': 'Severity'
                            },
                            {
                                'type': 'text',
                                'key': 'audit',
                                'name': 'Audit'
                            },
                            {
                                'type': 'text',
                                'key': 'risk',
                                'name': 'Risk'
                            },
                            {
                                'type': 'text',
                                'key': 'recommendation.description',
                                'name': 'Recommendations'
                            }
                        ],
                        'root_path': 'data.checks'
                    }
                },
                {
                    'type': 'table',
                    'name': 'Findings',
                    'options': {
                        'fields': [
                            {
                                'type': 'text',
                                'key': 'check_title',
                                'name': 'Check Title'
                            },
                            {
                                'type': 'enum',
                                'name': 'Status',
                                'key': 'status',
                                'options': {
                                    'FAIL': {
                                        'type': 'badge',
                                        'options': {
                                            'background_color': 'coral.500'
                                        }
                                    },
                                    'PASS': {
                                        'type': 'badge',
                                        'options': {
                                            'background_color': 'indigo.500'
                                        }
                                    },
                                    'INFO': {
                                        'type': 'badge',
                                        'options': {
                                            'background_color': 'peacock.500'
                                        }
                                    }
                                }
                            },
                            {
                                'type': 'text',
                                'key': 'resource_type',
                                'name': 'Resource Type'
                            },
                            {
                                'type': 'text',
                                'key': 'resource',
                                'name': 'Resource'
                            },
                            {
                                'type': 'text',
                                'key': 'region_code',
                                'name': 'Region',
                                'reference': 'inventory.Region'
                            },
                        ],
                        'root_path': 'data.findings'
                    }
                }
            ]
        }
    }
}


class CloudServiceType(BaseCloudServiceType):
    name: str
    group: str = 'Prowler'
    provider: str
    is_primary: bool = True
    is_major: bool = True
    metadata: dict = _METADATA
    labels: List[str] = ['Security', 'Compliance']
    tags: dict = {
        'spaceone:icon': 'https://spaceone-custom-assets.s3.ap-northeast-2.amazonaws.com/console-assets/icons/prowler.png'
    }
