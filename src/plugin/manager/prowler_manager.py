import os

import json
import time
import random
import logging
from typing import Generator, List

from natsort import natsorted
from prowler.lib.check.check import bulk_load_compliance_frameworks, bulk_load_checks_metadata
from spaceone.inventory.plugin.collector.lib import make_cloud_service, make_error_response

from plugin.error.custom import *
from plugin.manager.base import ResourceManager
from plugin.connector.prowler_connector import ProwlerConnector
from plugin.conf.collector_conf import *

_LOGGER = logging.getLogger("spaceone")


class ProwlerManager(ResourceManager):
    provider = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.name = None
        self.provider = None
        self.cloud_service_group = "Prowler"
        self.cloud_service_type = None
        self.service_code = None
        self.is_primary = True
        self.icon = "prowler.svg"
        self.labels = ["Security", "Compliance", "CSPM"]
        self.metadata_path = "metadata/prowler.yaml"
        self.prowler_connector = None
        self.requirement_info = {}
        self.checklist = []
        self.is_custom_checks = False
        self.checks_metadata = {}

    def collect_cloud_services(
            self, options: dict, secret_data: dict, schema: str
    ) -> Generator[dict, None, None]:
        self.provider = options.get("provider")
        self.cloud_service_type = options["compliance_framework"]

        if self.provider == "aws":
            self.is_primary = True
            self.name = f"AWS {self.cloud_service_type}"
        elif self.provider == "azure":
            self.name = f"Azure {self.cloud_service_type}"
        elif self.provider == "google_cloud":
            self.name = f"Google Cloud {self.cloud_service_type}"
        else:
            yield ERROR_INVALID_PARAMETER(
                key="options.provider", reason="Not supported provider."
            )

        self.checklist = options.get("check_list")
        self.prowler_connector = ProwlerConnector()
        self._check_compliance_framework()
        self._load_requirement_info()

        self._wait_random_time()

        check_results, err_message = self.prowler_connector.check(
            options, secret_data
        )

        # Return compliance results (Cloud Services)
        for compliance_result in self.make_compliance_results(check_results):
            yield make_cloud_service(
                name=compliance_result["name"],
                cloud_service_type=self.cloud_service_type,
                cloud_service_group=self.cloud_service_group,
                provider=self.provider,
                account=compliance_result["account"],
                data=compliance_result,
                region_code="global",
                reference={
                    "resource_id": compliance_result["reference"]["resource_id"],
                },
                data_format="grpc",
            )
        if err_message:
            _LOGGER.error(f"[{self.__repr__()}.prowler_connector.check] Error: {err_message}")
            raise Exception(err_message)

    def make_compliance_results(self, check_results: List[dict]) -> List[dict]:
        compliance_results = {}
        for check_result in check_results:
            check_id = check_result["metadata"]["event_code"]
            account = check_result["cloud"]["account"]["uid"]
            requirements = check_result["unmapped"].get("compliance", {}).get(
                self.cloud_service_type, []
            )
            for requirement_id in requirements:
                requirement_seq = next(
                    (requirement['Requirement_Seq']
                     for requirement in self.requirement_info[self.cloud_service_type]['Requirements']
                     if requirement['Id'] == requirement_id and check_id in requirement['Checks']
                     ),
                    None
                )

                compliance_id = (
                    f"prowler:{self.provider}:{account}:{self.cloud_service_type}:{requirement_id}:" 
                    f"{str(requirement_seq)}"
                ).lower()
                status = check_result["status_code"]
                region_code = check_result["cloud"]["region"]
                severity = SEVERITY_MAP.get(check_result["severity"], "UNKNOWN")
                score = SEVERITY_SCORE_MAP[severity]

                if compliance_id not in compliance_results:
                    compliance_results[
                        compliance_id
                    ] = self._make_base_compliance_result(
                        compliance_id, requirement_id, requirement_seq, check_id, severity, check_result
                    )

                check_exists = (
                        check_id in compliance_results[compliance_id]["data"]["checks"]
                )

                if compliance_results[compliance_id]["region_code"] != region_code:
                    compliance_results[compliance_id]["region_code"] = "global"

                compliance_results[compliance_id]["data"][
                    "severity"
                ] = self._update_severity(
                    compliance_results[compliance_id]["data"]["severity"], severity
                )

                compliance_results[compliance_id][
                    "data"
                ] = self._update_compliance_status_and_stats(
                    compliance_results[compliance_id]["data"], status, score
                )

                compliance_results[compliance_id]["data"]["findings"].append(
                    self._make_finding(check_result)
                )

                if not check_exists:
                    compliance_results[compliance_id]["data"]["checks"][
                        check_id
                    ] = self._make_check(check_result)

                compliance_results[compliance_id]["data"]["checks"][
                    check_id
                ] = self._update_check_status_and_stats(
                    compliance_results[compliance_id]["data"]["checks"][check_id],
                    status,
                    score,
                )

        return self._convert_results(compliance_results)

    def _convert_results(self, compliance_results):
        results = []
        for compliance_result in compliance_results.values():
            total_check_count = 0
            pass_check_count = 0
            fail_check_count = 0
            info_check_count = 0

            compliance_result["data"]["stats"]["score"][
                "percent"
            ] = self._calculate_score(compliance_result["data"]["stats"])

            changed_checks = []
            for check in compliance_result["data"]["checks"].values():
                total_check_count += 1
                if check["status"] == "FAIL":
                    fail_check_count += 1
                elif check["status"] == "INFO":
                    info_check_count += 1
                else:
                    pass_check_count += 1

                check["display"] = self._make_check_display(check["stats"])
                check["stats"]["score"]["percent"] = self._calculate_score(
                    check["stats"]
                )
                changed_checks.append(check)

            compliance_result["data"]["checks"] = changed_checks
            compliance_result["data"]["stats"]["checks"] = {
                "total": total_check_count,
                "pass": pass_check_count,
                "fail": fail_check_count,
                "info": info_check_count,
            }

            compliance_result["data"]["display"] = self._make_compliance_display(
                compliance_result["data"]["stats"]
            )

            results.append(compliance_result)

        compliance_ids = {}
        for key in compliance_results.keys():
            _, _, account, _, _, requirement_seq = key.split(":")
            if account not in compliance_ids:
                compliance_ids[account] = []
            compliance_ids[account].append(requirement_seq)

        for account in compliance_ids.keys():
            for requirement in self.requirement_info[self.cloud_service_type]['Requirements']:
                if str(requirement['Requirement_Seq']) not in compliance_ids.get(account, []):
                    compliance_id = (
                        f"prowler:{self.provider}:{account}:{self.cloud_service_type}:{requirement['Id']}:"
                        f"{str(requirement['Requirement_Seq'])}"
                    ).lower()
                    compliance_results[
                        compliance_id
                    ] = self._make_base_compliance_result(
                        compliance_id, requirement['Id'], requirement['Requirement_Seq'], None, None, None
                    )
                    results.append(compliance_results[compliance_id])

        return results

    @staticmethod
    def _make_check_display(check_stats):
        findings_pass = check_stats["findings"]["pass"]
        findings_total = check_stats["findings"]["total"]

        return {"findings": f"{findings_pass}/{findings_total}"}

    @staticmethod
    def _calculate_score(stats):
        score_pass = stats["score"]["pass"]
        score_fail = stats["score"]["fail"]
        score_total = score_pass + score_fail

        if score_total == 0:
            return 0
        else:
            return round(score_pass / score_total * 100, 1)

    @staticmethod
    def _make_compliance_display(compliance_data_stats):
        checks_pass = compliance_data_stats["checks"]["pass"]
        checks_total = compliance_data_stats["checks"]["total"]
        findings_pass = compliance_data_stats["findings"]["pass"]
        findings_total = compliance_data_stats["findings"]["total"]

        return {
            "checks": f"{checks_pass}/{checks_total}",
            "findings": f"{findings_pass}/{findings_total}",
        }

    @staticmethod
    def _update_severity(old_severity: str, new_severity: str) -> str:
        if SEVERITY_SCORE_MAP[old_severity] < SEVERITY_SCORE_MAP[new_severity]:
            return new_severity
        return old_severity

    def _make_check(self, check_result: dict) -> dict:
        check = {
            "check_id": check_result["metadata"]["event_code"],
            "check_title": check_result["finding_info"]["title"],
            "service": check_result["resources"][0]["group"]["name"],
            "sub_service": "",
            "check_type": check_result["unmapped"]["check_type"],
            "status": "PASS",
            "severity": SEVERITY_MAP.get(check_result["severity"], "UNKNOWN"),
            "risk": check_result["risk_details"],
            "remediation": self._make_remediation(check_result["remediation"]),
            "stats": {
                "score": {"pass": 0, "fail": 0, "percent": 0},
                "findings": {
                    "total": 0,
                    "pass": 0,
                    "fail": 0,
                    "info": 0,
                },
            },
        }

        return check

    @staticmethod
    def _make_remediation(remediation_info):
        return {
            "description": remediation_info.get("desc", ""),
            "link": remediation_info["references"],
        }

    @staticmethod
    def _make_finding(check_result: dict) -> dict:
        return {
            "finding_id": check_result["finding_info"]["uid"],
            "check_id": check_result["metadata"]["event_code"],
            "check_title": check_result["finding_info"]["title"],
            "status": check_result["status_code"],
            "status_extended": check_result["status_detail"],
            "resource": check_result["resources"][0]["name"] or check_result["resources"][0]["uid"],
            "resource_type": check_result["resources"][0]["type"],
            "region_code": check_result["cloud"]["region"],
        }

    @staticmethod
    def _update_check_status_and_stats(check: dict, status: str, score: int) -> dict:
        check["stats"]["findings"]["total"] += 1

        if status == "FAIL":
            check["status"] = "FAIL"
            check["stats"]["score"]["fail"] += score
            check["stats"]["findings"]["fail"] += 1
        elif status == "INFO":
            if check["status"] != "FAIL":
                check["status"] = "INFO"
            check["stats"]["findings"]["info"] += 1
        else:
            check["stats"]["score"]["pass"] += score
            check["stats"]["findings"]["pass"] += 1

        return check

    @staticmethod
    def _update_compliance_status_and_stats(
        compliance_result_data: dict, status: str, score: int
    ) -> dict:
        compliance_result_data["stats"]["findings"]["total"] += 1

        if status == "FAIL":
            compliance_result_data["status"] = "FAIL"
            compliance_result_data["stats"]["score"]["fail"] += score
            compliance_result_data["stats"]["findings"]["fail"] += 1
        elif status == "INFO":
            if compliance_result_data["status"] != "FAIL":
                compliance_result_data["status"] = "INFO"

            compliance_result_data["stats"]["findings"]["info"] += 1
        else:
            compliance_result_data["stats"]["score"]["pass"] += score
            compliance_result_data["stats"]["findings"]["pass"] += 1

        # if not check_exists:
        #     compliance_result_data['stats']['checks']['total'] += 1
        #     if status == 'FAIL':
        #         compliance_result_data['stats']['checks']['fail'] += 1
        #     elif status == 'PASS':
        #         compliance_result_data['stats']['checks']['pass'] += 1
        #     else:
        #         compliance_result_data['stats']['checks']['info'] += 1

        return compliance_result_data

    def _make_base_compliance_result(
            self, compliance_id: str, requirement_id: str, requirement_seq: int, check_id: str, severity: str,
            check_result: dict
    ) -> dict:
        requirement_name, supported, requirement_skip = next(
            ((requirement['Description'], requirement['Supported'], requirement['Skip'])
             for requirement in self.requirement_info[self.cloud_service_type]['Requirements']
             if requirement['Requirement_Seq'] == requirement_seq
             ),
            (None, None, None)
        )
        account = compliance_id.split(":")[2]

        compliance_result = {
            "name": requirement_name,
            "reference": {
                "resource_id": compliance_id,
            },
            "requirement_seq": requirement_seq,
            "supported": supported,
            "data": {
                "requirement_id": requirement_id,
                "description": check_result["finding_info"]["desc"] if check_id else "",
                "status": "SKIP" if requirement_skip else ("PASS" if check_id else "UNKNOWN"),
                "severity": severity if check_id else "",
                "service": check_result["resources"][0]["group"]["name"] if check_id else "",
                "checks": {},
                "findings": [],
                "display": {
                    "score": "",
                    "score_percent": "",
                    "checks": "",
                    "findings": "",
                },
                "stats": {
                    "score": {"pass": 0, "fail": 0, "percent": 0},
                    "checks": {
                        "total": 0,
                        "pass": 0,
                        "fail": 0,
                        "info": 0,
                    },
                    "findings": {
                        "total": 0,
                        "pass": 0,
                        "fail": 0,
                        "info": 0,
                    },
                },
            },
            "metadata": {
                "view": {
                    "sub_data": {
                        "reference": {
                            "resource_type": "inventory.CloudServiceType",
                            "options": {
                                "provider": self.provider,
                                "cloud_service_group": self.cloud_service_group,
                                "cloud_service_type": self.cloud_service_type,
                            },
                        }
                    }
                }
            },
            "account": account,
            "provider": self.provider,
            "cloud_service_group": self.cloud_service_group,
            "cloud_service_type": self.cloud_service_type,
            "region_code": check_result["cloud"]["region"] if check_id else "global",
        }

        return compliance_result

    @staticmethod
    def _wait_random_time():
        random_time = round(random.uniform(0, 5), 2)
        _LOGGER.debug(f"[_wait_random_time] sleep time: {random_time}")

        time.sleep(random_time)

    def _check_compliance_framework(self):
        all_compliance_frameworks = list(COMPLIANCE_FRAMEWORKS[self.provider].keys())
        if self.cloud_service_type not in all_compliance_frameworks:
            raise ERROR_INVALID_PARAMETER(
                key="options.compliance_framework",
                reason=f"Not supported compliance framework. "
                       f"(compliance_frameworks = {all_compliance_frameworks})",
            )

    def _load_requirement_info(self):
        frameworks = {}
        compliance_framework = COMPLIANCE_FRAMEWORKS[self.provider][self.cloud_service_type]
        compliance_frameworks = bulk_load_compliance_frameworks(
            self.provider if self.provider != "google_cloud" else "gcp"
        )
        sorted_requirements = natsorted(compliance_frameworks[compliance_framework].Requirements,
                                        key=lambda x: (x.Id, x.Description))
        frameworks[self.cloud_service_type] = json.loads(compliance_frameworks[compliance_framework].json())
        frameworks[self.cloud_service_type]['Requirements'] = []

        for i, requirement in enumerate(sorted_requirements):
            requirement_json = json.loads(requirement.json())
            requirement_checks = requirement_json.get('Checks', [])
            requirement_json['Requirement_Seq'] = i + 1
            requirement_json['Supported'] = bool(requirement_checks)
            requirement_json['Skip'] = not requirement_checks or (
                    bool(self.checklist) and not bool(set(self.checklist) & set(requirement_checks)))
            frameworks[self.cloud_service_type]['Requirements'].append(requirement_json)

        self.requirement_info = frameworks
