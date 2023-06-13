import logging
from typing import Generator, List

from cloudforet.plugin.manager.collector_manager import CollectorManager
from cloudforet.plugin.connector.aws_prowler_connector import AWSProwlerConnector
from cloudforet.plugin.model.prowler.cloud_service_type import CloudServiceType

_LOGGER = logging.getLogger(__name__)

_SEVERITY_MAP = {
    'critical': 'CRITICAL',
    'high': 'HIGH',
    'medium': 'MEDIUM',
    'low': 'LOW',
    'informational': 'INFORMATIONAL',
}

_SEVERITY_SCORE_MAP = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
    'INFORMATIONAL': 0,
    'UNKNOWN': 1
}


class AWSProwlerManager(CollectorManager):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.aws_prowler_connector: AWSProwlerConnector = self.locator.get_connector(AWSProwlerConnector)
        self.provider = 'aws'
        self.cloud_service_group = 'Prowler'
        self.cloud_service_type = 'CIS-1.5'
        self.region_name = 'global'

    def collect(self, options: dict, secret_data: dict, schema: str) -> Generator[dict, None, None]:
        try:
            check_results = self.aws_prowler_connector.check(options, secret_data, schema)
            compliance_results = self.make_compliance_results(check_results)

            # Return Cloud Service Type
            cloud_service_type = CloudServiceType(name=self.cloud_service_type, provider=self.provider)
            yield self.make_response(cloud_service_type.dict(),
                                     {'1': ['name', 'group', 'provider']},
                                     resource_type='inventory.CloudServiceType')

            # Return compliance results (Cloud Services)
            for compliance_result in compliance_results:
                yield self.make_response(compliance_result, {'1': [
                    'reference.resource_id', 'provider', 'cloud_service_type', 'cloud_service_group', 'account']})

        except Exception as e:
            yield self.error_response(e)

    def make_compliance_results(self, check_results: List[dict]) -> List[dict]:
        compliance_results = {}
        for check_result in check_results:
            account = check_result['AccountId']
            requirements = check_result.get('Compliance', {}).get(self.cloud_service_type, [])
            for requirement_id in requirements:
                compliance_id = f'{self.cloud_service_type}:{requirement_id}:{account}'
                check_id = check_result['CheckID']
                status = check_result['Status']
                region_code = check_result['Region']
                severity = _SEVERITY_MAP.get(check_result['Severity'], 'UNKNOWN')
                score = _SEVERITY_SCORE_MAP[severity]

                if compliance_id not in compliance_results:
                    compliance_results[compliance_id] = self._make_base_compliance_result(
                        compliance_id, requirement_id, severity, check_result)

                check_exists = check_id in compliance_results[compliance_id]['data']['checks']

                if compliance_results[compliance_id]['region_code'] != region_code:
                    compliance_results[compliance_id]['region_code'] = self.region_name

                compliance_results[compliance_id]['data']['severity'] = self._update_severity(
                    compliance_results[compliance_id]['data']['severity'], severity)

                compliance_results[compliance_id]['data'] = self._update_compliance_status_and_stats(
                    compliance_results[compliance_id]['data'], status, score, check_exists)

                compliance_results[compliance_id]['data']['findings'].append(self._make_finding(check_result))

                if not check_exists:
                    compliance_results[compliance_id]['data']['checks'][check_id] = self._make_check(check_result)

                compliance_results[compliance_id]['data']['checks'][check_id] = self._update_check_status_and_stats(
                    compliance_results[compliance_id]['data']['checks'][check_id], status, score)

        return self._convert_results(compliance_results)

    def _convert_results(self, compliance_results):
        results = []
        for compliance_result in compliance_results.values():
            compliance_result['data']['display'] = self._make_compliance_display(compliance_result['data']['stats'])
            compliance_result['data']['stats']['score']['percent'] = \
                self._calculate_score(compliance_result['data']['stats'])

            changed_checks = []
            for check in compliance_result['data']['checks'].values():
                check['display'] = self._make_check_display(check['stats'])
                check['stats']['score']['percent'] = self._calculate_score(check['stats'])
                changed_checks.append(check)

            compliance_result['data']['checks'] = changed_checks

            results.append(compliance_result)

        return results

    @staticmethod
    def _make_check_display(check_stats):
        findings_pass = check_stats['findings']['pass']
        findings_total = check_stats['findings']['total']

        return {
            'findings': f'{findings_pass}/{findings_total}'
        }

    @staticmethod
    def _calculate_score(stats):
        score_pass = stats['score']['pass']
        score_total = stats['score']['total']

        return round(score_pass / score_total * 100, 1)

    @staticmethod
    def _make_compliance_display(compliance_data_stats):
        checks_pass = compliance_data_stats['checks']['pass']
        checks_total = compliance_data_stats['checks']['total']
        findings_pass = compliance_data_stats['findings']['pass']
        findings_total = compliance_data_stats['findings']['total']

        return {
            'checks': f'{checks_pass}/{checks_total}',
            'findings': f'{findings_pass}/{findings_total}'
        }

    @staticmethod
    def _update_severity(old_severity: str, new_severity: str) -> str:
        if _SEVERITY_SCORE_MAP[old_severity] < _SEVERITY_SCORE_MAP[new_severity]:
            return new_severity
        return old_severity

    def _make_check(self, check_result: dict) -> dict:
        check = {
            'check_id': check_result['CheckID'],
            'check_title': check_result['CheckTitle'],
            'service': check_result['ServiceName'],
            'sub_service': check_result['SubServiceName'],
            'check_type': check_result['CheckType'],
            'status': 'PASS',
            'severity': _SEVERITY_MAP.get(check_result['Severity'], 'UNKNOWN'),
            'audit': check_result['StatusExtended'],
            'risk': check_result['Risk'],
            'remediation': self._make_remediation(check_result['Remediation']),
            'stats': {
                'score': {
                    'total': 0,
                    'pass': 0,
                    'fail': 0,
                    'percent': 0
                },
                'findings': {
                    'total': 0,
                    'pass': 0,
                    'fail': 0
                }
            }
        }

        return check

    @staticmethod
    def _make_remediation(remediation_info):
        recommendation = remediation_info.get('Recommendation', {})
        return {
            'description': recommendation.get('Text', ''),
            'link': recommendation.get('Url', ''),
        }

    @staticmethod
    def _make_finding(check_result: dict) -> dict:
        return {
            'finding_id': check_result['FindingUniqueId'],
            'check_id': check_result['CheckID'],
            'check_title': check_result['CheckTitle'],
            'status': check_result['Status'],
            'resource': check_result['ResourceId'] or check_result['ResourceArn'],
            'resource_type': check_result['ResourceType'],
            'region_code': check_result['Region'],
        }

    @staticmethod
    def _update_check_status_and_stats(check: dict, status: str, score: int) -> dict:
        check['stats']['score']['total'] += score
        check['stats']['findings']['total'] += 1

        if status == 'FAIL':
            check['status'] = 'FAIL'
            check['stats']['score']['fail'] += score
            check['stats']['findings']['fail'] += 1
        else:
            check['stats']['score']['pass'] += score
            check['stats']['findings']['pass'] += 1

        return check

    @staticmethod
    def _update_compliance_status_and_stats(compliance_result_data: dict, status: str, score: int,
                                            check_exists: bool) -> dict:
        compliance_result_data['stats']['score']['total'] += score
        compliance_result_data['stats']['findings']['total'] += 1

        if status == 'FAIL':
            compliance_result_data['status'] = 'FAIL'
            compliance_result_data['stats']['score']['fail'] += score
            compliance_result_data['stats']['findings']['fail'] += 1
        else:
            compliance_result_data['stats']['score']['pass'] += score
            compliance_result_data['stats']['findings']['pass'] += 1

        if not check_exists:
            compliance_result_data['stats']['checks']['total'] += 1
            if status == 'FAIL':
                compliance_result_data['stats']['checks']['fail'] += 1
            else:
                compliance_result_data['stats']['checks']['pass'] += 1


        return compliance_result_data

    def _make_base_compliance_result(self, compliance_id: str, requirement_id: str, severity: str,
                                     check_result: dict) -> dict:
        compliance_result = {
            'name': check_result['Description'],
            'reference': {
                'resource_id': compliance_id,
            },
            'data': {
                'requirement_id': requirement_id,
                # 'description': check_result['Description'],
                'status': 'PASS',
                'severity': severity,
                'service': check_result['ServiceName'],
                'checks': {},
                'findings': [],
                'display': {
                    'score': '',
                    'score_percent': '',
                    'checks': '',
                    'findings': ''
                },
                'stats': {
                    'score': {
                        'total': 0,
                        'pass': 0,
                        'fail': 0,
                        'percent': 0
                    },
                    'checks': {
                        'total': 0,
                        'pass': 0,
                        'fail': 0
                    },
                    'findings': {
                        'total': 0,
                        'pass': 0,
                        'fail': 0
                    }
                }
            },
            'metadata': {
                'view': {
                    'sub_data': {
                        'reference': {
                            'resource_type': 'inventory.CloudServiceType',
                            'options': {
                                'provider': self.provider,
                                'cloud_service_group': self.cloud_service_group,
                                'cloud_service_type': self.cloud_service_type,
                            }
                        }
                    }
                }
            },
            'account': check_result['AccountId'],
            'provider': self.provider,
            'cloud_service_group': self.cloud_service_group,
            'cloud_service_type': self.cloud_service_type,
            'region_code': check_result['Region']
        }

        return compliance_result
