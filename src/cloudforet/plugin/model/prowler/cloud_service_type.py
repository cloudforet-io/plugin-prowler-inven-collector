from typing import List
from cloudforet.plugin.model.cloud_service_type_model import BaseCloudServiceType

_METADATA = {
    'query_sets': [
        {
            'name': 'Prowler Status',
            'query_options': {
                'group_by': [
                    'data.status',
                    'data.severity',
                    'data.service'
                ],
                'fields': {
                    'compliance_count': {
                        'operator': 'count'
                    },
                    'fail_check_count': {
                        'key': 'data.stats.checks.fail',
                        'operator': 'sum'
                    },
                    'pass_check_count': {
                        'key': 'data.stats.checks.pass',
                        'operator': 'sum'
                    },
                    'info_check_count': {
                        'key': 'data.stats.checks.info',
                        'operator': 'sum'
                    },
                    'fail_finding_count': {
                        'key': 'data.stats.findings.fail',
                        'operator': 'sum'
                    },
                    'pass_finding_count': {
                        'key': 'data.stats.findings.pass',
                        'operator': 'sum'
                    },
                    'info_finding_count': {
                        'key': 'data.stats.findings.info',
                        'operator': 'sum'
                    },
                    'fail_score': {
                        'key': 'data.stats.score.fail',
                        'operator': 'sum'
                    },
                    'pass_score': {
                        'key': 'data.stats.score.pass',
                        'operator': 'sum'
                    }
                }
            }
        }
    ],
    'view': {
        'search': [
            {
                'key': 'data.requirement_id',
                'name': 'Requirement ID'
            },
            {
                'key': 'data.status',
                'name': 'Status'
            },
            {
                'key': 'data.stats.score.percent',
                'name': 'Compliance Score',
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
                    'default_sort': {
                        'key': 'data.requirement_id',
                        'desc': False
                    },
                    'fields': [
                        {
                            'type': 'text',
                            'key': 'data.requirement_id',
                            'name': 'Requirement ID'
                        },
                        {
                            'type': 'text',
                            'key': 'data.description',
                            'name': 'Description'
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
                            'key': 'data.stats.score.percent',
                            'name': 'Compliance Score'
                        },
                        {
                            'type': 'text',
                            'key': 'data.severity',
                            'name': 'Severity'
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
                    'filter': [
                        # {'key': 'provider', 'value': 'aws', 'operator': 'eq'},
                        # {'key': 'cloud_service_group', 'value': 'Prowler', 'operator': 'eq'},
                    ]
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
                        # {'key': 'provider', 'value': 'aws', 'operator': 'eq'},
                        # {'key': 'cloud_service_group', 'value': 'Prowler', 'operator': 'eq'},
                        {'key': 'data.status', 'value': 'FAIL', 'operator': 'eq'}
                    ]
                }
            },
            {
                'name': 'Compliance Score',
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
                            'group': {
                                'fields': [
                                    {
                                        'key': 'data.stats.score.percent',
                                        'name': 'value',
                                        'operator': 'average'
                                    }
                                ]
                            }
                        }
                    ],
                    'filter': [
                        # {'key': 'provider', 'value': 'aws', 'operator': 'eq'},
                        # {'key': 'cloud_service_group', 'value': 'Prowler', 'operator': 'eq'},
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
                                'key': 'severity',
                                'name': 'Severity'
                            },
                            {
                                'type': 'text',
                                'key': 'service',
                                'name': 'Service'
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
                                'key': 'remediation.description',
                                'name': 'Remediation'
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
                                'name': 'Resource',
                                'reference': {
                                    'resource_type': 'inventory.CloudService',
                                    'reference_key': 'reference.resource_id'
                                }
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
    group: str = 'Prowler'
    is_primary: bool = True
    is_major: bool = True
    metadata: dict = _METADATA
    labels: List[str] = ['Security', 'Compliance']
    tags: dict = {
        'spaceone:icon': 'https://spaceone-custom-assets.s3.ap-northeast-2.amazonaws.com/console-assets/icons/prowler.svg'
    }
