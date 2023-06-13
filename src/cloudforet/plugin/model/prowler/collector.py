from cloudforet.plugin.model.plugin_info_model import PluginInfo, PluginMetadata, ResourceType

SEVERITIES = {
    'Critical': 'critical',
    'High': 'high',
    'Medium': 'medium',
    'Low': 'low',
    'Informational': 'informational',
}

COMPLIANCE_TYPES = {
    'aws': {
        'CIS-1.4': 'cis_1.4_aws',
        'CIS-1.5': 'cis_1.5_aws',
        'CISA': 'cisa_aws',
        'SOC2': 'soc2_aws',
        'GDPR': 'gdpr_aws',
        'HIPAA': 'hipaa_aws',
        'AWS-FSBP': 'aws_foundational_security_best_practices_aws',
        'GxP-21-CFR-Part-11': 'gxp_21_cfr_part_11_aws',
        'GxP-EU-Annex-11': 'gxp_eu_annex_11_aws',
        'NIST-800-171-R2': 'nist_800_171_revision_2_aws',
        'NIST-800-53-R4': 'nist_800_53_revision_4_aws',
        'NIST-800-53-R5': 'nist_800_53_revision_5_aws',
        'ENS-2022-RD': 'ens_rd2022_aws',
        'NIST-CSF-1.1': 'nist_csf_1.1_aws',
        'AWS-CT-Guardrails': 'aws_audit_manager_control_tower_guardrails_aws',
        'RBI-CSF': 'rbi_cyber_security_framework_aws',
        'FFIEC': 'ffiec_aws',
        'PCI-3.2.1': 'pci_3.2.1_aws',
        'FedRAMP-Moderate-R4': 'fedramp_moderate_revision_4_aws',
        'FedRAMP-Low-R4': 'fedramp_low_revision_4_aws',
    },
    'google_cloud': {
        'Google-Cloud-Standard': '',
    },
    'azure': {
        'Azure-Standard': '',
    }
}

SERVICES = {
    'aws': {
        'AccessAnalyzer': 'accessanalyzer',
        'Account': 'account',
        'ACM': 'acm',
        'APIGateway': 'apigateway',
        'APIGatewayV2': 'apigatewayv2',
        'AppStream': 'appstream',
        'AutoScaling': 'autoscaling',
        'Lambda': 'awslambda',
        'Backup': 'backup',
        'CloudFormation': 'cloudformation',
        'CloudFront': 'cloudfront',
        'CloudTrail': 'cloudtrail',
        'CloudWatch': 'cloudwatch',
        'CodeArtifact': 'codeartifact',
        'CodeBuild': 'codebuild',
        'ConfigService': 'config',
        'DirectoryService': 'directoryservice',
        'DRS': 'drs',
        'DynamoDB': 'dynamodb',
        'EC2': 'ec2',
        'ECR': 'ecr',
        'ECS': 'ecs',
        'EFS': 'efs',
        'EKS': 'eks',
        'ELB': 'elb',
        'ELBv2': 'elbv2',
        'EMR': 'emr',
        'Glacier': 'glacier',
        'Glue': 'glue',
        'GuardDuty': 'guardduty',
        'IAM': 'iam',
        'Inspector2': 'inspector2',
        'KMS': 'kms',
        'Macie': 'macie',
        'OpenSearchService': 'opensearch',
        'Organizations': 'organizations',
        'RDS': 'rds',
        'Redshift': 'redshift',
        'ResourceExplorer2': 'resourceexplorer2',
        'Route53': 'route53',
        'S3': 's3',
        'SageMaker': 'sagemaker',
        'SecretsManager': 'secretsmanager',
        'SecurityHub': 'securityhub',
        'Sheild': 'shield',
        'SNS': 'sns',
        'SQS': 'sqs',
        'SSM': 'ssm',
        'SSMIncidents': 'ssmincidents',
        'TrustedAdvisor': 'trustedadvisor',
        'VPC': 'vpc',
        'WorkSpaces': 'workspaces',
    },
    'google_cloud': {
        'BigQuery': 'bigquery',
        'CloudSQL': 'cloudsql',
        'CloudStorage': 'cloudstorage',
        'ComputeEngine': 'compute',
        'IAM': 'iam',
        'KMS': 'kms',
        'Logging': 'logging',
    },
    'azure': {
        'Defender': 'defender',
        'IAM': 'iam',
        'Storage': 'storage',
    }
}


class AWSPluginInfo(PluginInfo):
    metadata: PluginMetadata = {
        'supported_resource_type': [
            ResourceType.cloud_service,
            ResourceType.cloud_service_type,
            ResourceType.region
        ],
        'options_schema': {
            'required': ['provider', 'compliance_type'],
            'type': 'object',
            'properties': {
                'provider': {
                    'title': 'Provider',
                    'type': 'string',
                    'default': 'google_cloud',
                    'disabled': True
                },
                'compliance_type': {
                    'title': 'Compliance Type',
                    'type': 'string',
                    'enum': list(COMPLIANCE_TYPES['aws'].keys()),
                },
                'services': {
                    'title': 'Services',
                    'type': 'array',
                    'items': {
                        'enum': list(SERVICES['aws'].keys())
                    }
                },
                'severities': {
                    'title': 'Severities',
                    'type': 'array',
                    'items': {
                        'enum': list(SEVERITIES.keys())
                    }
                }
            }
        }
    }


class GoogleCloudPluginInfo(PluginInfo):
    metadata: PluginMetadata = {
        'supported_resource_type': [
            ResourceType.cloud_service,
            ResourceType.cloud_service_type,
            ResourceType.region
        ],
        'options_schema': {
            'required': ['provider', 'compliance_type'],
            'type': 'object',
            'properties': {
                'provider': {
                    'title': 'Provider',
                    'type': 'string',
                    'default': 'google_cloud',
                    'disabled': True
                },
                'compliance_type': {
                    'title': 'Compliance Type',
                    'type': 'string',
                    'enum': list(COMPLIANCE_TYPES['google_cloud'].keys()),
                },
                'services': {
                    'title': 'Services',
                    'type': 'array',
                    'items': {
                        'enum': list(SERVICES['google_cloud'].keys())
                    }
                },
                'severities': {
                    'title': 'Severities',
                    'type': 'array',
                    'items': {
                        'enum': list(SEVERITIES.keys())
                    }
                }
            }
        }
    }


class AzurePluginInfo(PluginInfo):
    metadata: PluginMetadata = {
        'supported_resource_type': [
            ResourceType.cloud_service,
            ResourceType.cloud_service_type,
            ResourceType.region
        ],
        'options_schema': {
            'required': ['provider', 'compliance_type'],
            'type': 'object',
            'properties': {
                'provider': {
                    'title': 'Provider',
                    'type': 'string',
                    'default': 'google_cloud',
                    'disabled': True
                },
                'compliance_type': {
                    'title': 'Compliance Type',
                    'type': 'string',
                    'enum': list(COMPLIANCE_TYPES['azure'].keys()),
                },
                'services': {
                    'title': 'Services',
                    'type': 'array',
                    'items': {
                        'enum': list(SERVICES['azure'].keys())
                    }
                },
                'severities': {
                    'title': 'Severities',
                    'type': 'array',
                    'items': {
                        'enum': list(SEVERITIES.keys())
                    }
                }
            }
        }
    }
