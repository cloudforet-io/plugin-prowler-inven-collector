import time
import random
import logging
from typing import Generator, List
from prowler.lib.check.check import bulk_load_compliance_frameworks

from cloudforet.plugin.error.custom import *
from cloudforet.plugin.manager.collector_manager import CollectorManager
from cloudforet.plugin.connector.aws_prowler_connector import AWSProwlerConnector
from cloudforet.plugin.model.prowler.cloud_service_type import CloudServiceType
from cloudforet.plugin.model.prowler.collector import COMPLIANCE_FRAMEWORKS

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
        self.cloud_service_type = None
        self.compliance_framework_info = {}

    def collect(self, options: dict, secret_data: dict, schema: str) -> Generator[dict, None, None]:
        self.cloud_service_type = options['compliance_framework']
        self._check_compliance_framework()
        self._load_compliance_framework_info()

        self._wait_random_time()

        try:
            check_results = self.aws_prowler_connector.check(options, secret_data, schema)

            # Return Cloud Service Type
            cloud_service_type = CloudServiceType(name=self.cloud_service_type, provider=self.provider)
            cloud_service_type.metadata['query_sets'][0]['name'] = f'AWS {self.cloud_service_type}'
            yield self.make_response(cloud_service_type.dict(),
                                     {'1': ['name', 'group', 'provider']},
                                     resource_type='inventory.CloudServiceType')

            # Return compliance results (Cloud Services)
            for compliance_result in self.make_compliance_results(check_results):
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
                    compliance_results[compliance_id]['region_code'] = 'global'

                compliance_results[compliance_id]['data']['severity'] = self._update_severity(
                    compliance_results[compliance_id]['data']['severity'], severity)

                compliance_results[compliance_id]['data'] = self._update_compliance_status_and_stats(
                    compliance_results[compliance_id]['data'], status, score)

                compliance_results[compliance_id]['data']['findings'].append(self._make_finding(check_result))

                if not check_exists:
                    compliance_results[compliance_id]['data']['checks'][check_id] = self._make_check(check_result)

                compliance_results[compliance_id]['data']['checks'][check_id] = self._update_check_status_and_stats(
                    compliance_results[compliance_id]['data']['checks'][check_id], status, score)

        return self._convert_results(compliance_results)

    def _convert_results(self, compliance_results):
        results = []
        for compliance_result in compliance_results.values():
            total_check_count = 0
            pass_check_count = 0
            fail_check_count = 0
            info_check_count = 0

            compliance_result['data']['stats']['score']['percent'] = \
                self._calculate_score(compliance_result['data']['stats'])

            changed_checks = []
            for check in compliance_result['data']['checks'].values():
                total_check_count += 1
                if check['status'] == 'FAIL':
                    fail_check_count += 1
                elif check['status'] == 'INFO':
                    info_check_count += 1
                else:
                    pass_check_count += 1

                check['display'] = self._make_check_display(check['stats'])
                check['stats']['score']['percent'] = self._calculate_score(check['stats'])
                changed_checks.append(check)

            compliance_result['data']['checks'] = changed_checks
            compliance_result['data']['stats']['checks'] = {
                'total': total_check_count,
                'pass': pass_check_count,
                'fail': fail_check_count,
                'info': info_check_count
            }

            compliance_result['data']['display'] = self._make_compliance_display(compliance_result['data']['stats'])

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
        score_fail = stats['score']['fail']
        score_total = score_pass + score_fail

        if score_total == 0:
            return 0
        else:
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
            'risk': check_result['Risk'],
            'remediation': self._make_remediation(check_result['Remediation']),
            'stats': {
                'score': {
                    'pass': 0,
                    'fail': 0,
                    'percent': 0
                },
                'findings': {
                    'total': 0,
                    'pass': 0,
                    'fail': 0,
                    'info': 0,
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
            'status_extended': check_result['StatusExtended'],
            'resource': check_result['ResourceId'] or check_result['ResourceArn'],
            'resource_type': check_result['ResourceType'],
            'region_code': check_result['Region'],
        }

    @staticmethod
    def _update_check_status_and_stats(check: dict, status: str, score: int) -> dict:
        check['stats']['findings']['total'] += 1

        if status == 'FAIL':
            check['status'] = 'FAIL'
            check['stats']['score']['fail'] += score
            check['stats']['findings']['fail'] += 1
        elif status == 'INFO':
            if check['status'] != 'FAIL':
                check['status'] = 'INFO'
            check['stats']['findings']['info'] += 1
        else:
            check['stats']['score']['pass'] += score
            check['stats']['findings']['pass'] += 1

        return check

    @staticmethod
    def _update_compliance_status_and_stats(compliance_result_data: dict, status: str, score: int) -> dict:
        compliance_result_data['stats']['findings']['total'] += 1

        if status == 'FAIL':
            compliance_result_data['status'] = 'FAIL'
            compliance_result_data['stats']['score']['fail'] += score
            compliance_result_data['stats']['findings']['fail'] += 1
        elif status == 'INFO':
            if compliance_result_data['status'] != 'FAIL':
                compliance_result_data['status'] = 'INFO'

            compliance_result_data['stats']['findings']['info'] += 1
        else:
            compliance_result_data['stats']['score']['pass'] += score
            compliance_result_data['stats']['findings']['pass'] += 1

        # if not check_exists:
        #     compliance_result_data['stats']['checks']['total'] += 1
        #     if status == 'FAIL':
        #         compliance_result_data['stats']['checks']['fail'] += 1
        #     elif status == 'PASS':
        #         compliance_result_data['stats']['checks']['pass'] += 1
        #     else:
        #         compliance_result_data['stats']['checks']['info'] += 1

        return compliance_result_data

    def _make_base_compliance_result(self, compliance_id: str, requirement_id: str, severity: str,
                                     check_result: dict) -> dict:
        compliance_result = {
            'name': self.compliance_framework_info[requirement_id],
            'reference': {
                'resource_id': compliance_id,
            },
            'data': {
                'requirement_id': requirement_id,
                'description': check_result['Description'],
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
                        'pass': 0,
                        'fail': 0,
                        'percent': 0
                    },
                    'checks': {
                        'total': 0,
                        'pass': 0,
                        'fail': 0,
                        'info': 0,
                    },
                    'findings': {
                        'total': 0,
                        'pass': 0,
                        'fail': 0,
                        'info': 0,
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

    @staticmethod
    def _wait_random_time():
        random_time = round(random.uniform(0, 5), 2)
        _LOGGER.debug(f'[_wait_random_time] sleep time: {random_time}')

        time.sleep(random_time)

    def _check_compliance_framework(self):
        all_compliance_frameworks = list(COMPLIANCE_FRAMEWORKS['aws'].keys())
        if self.cloud_service_type not in all_compliance_frameworks:
            raise ERROR_INVALID_PARAMETER(key='options.compliance_framework',
                                          reason=f'Not supported compliance framework. '
                                                 f'(compliance_frameworks = {all_compliance_frameworks})')

    def _load_compliance_framework_info(self):
        compliance_framework = COMPLIANCE_FRAMEWORKS['aws'][self.cloud_service_type]
        compliance_frameworks = bulk_load_compliance_frameworks(self.provider)
        for requirement in compliance_frameworks[compliance_framework].Requirements:
            self.compliance_framework_info[requirement.Id] = requirement.Description
