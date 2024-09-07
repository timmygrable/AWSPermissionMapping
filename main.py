import boto3
import json
import re
import time
import logging
from botocore.exceptions import ClientError, ParamValidationError
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
import random

import backoff

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

MAX_RETRIES = 5
BASE_DELAY = 1
MAX_DELAY = 60

class AWSPermissionMapper:
    def __init__(self, service: str, region: str = "us-east-1", max_workers: int = 10):
        self.service = service
        self.region = region
        self.max_workers = max_workers
        self.iam = boto3.client("iam")
        self.client = boto3.client(service, region_name=region)
        self.role_name: Optional[str] = None

    @backoff.on_exception(backoff.expo, ClientError, max_tries=MAX_RETRIES, jitter=backoff.full_jitter)
    def create_test_role(self) -> Optional[str]:
        role_name = f"TempTestRole-{int(time.time())}"
        try:
            self.iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": f"{self.service}.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }],
                }),
            )
            self.iam.get_waiter("role_exists").wait(RoleName=role_name)
            return role_name
        except ClientError as e:
            logger.error(f"Error creating role: {e}")
            return None

    @backoff.on_exception(backoff.expo, ClientError, max_tries=MAX_RETRIES, jitter=backoff.full_jitter)
    def delete_test_role(self):
        if not self.role_name:
            return
        try:
            for policy in self.iam.list_role_policies(RoleName=self.role_name)["PolicyNames"]:
                self.iam.delete_role_policy(RoleName=self.role_name, PolicyName=policy)
            self.iam.delete_role(RoleName=self.role_name)
        except ClientError as e:
            logger.error(f"Error during cleanup: {e}")

    @backoff.on_exception(backoff.expo, (ClientError, ParamValidationError), max_tries=MAX_RETRIES, jitter=backoff.full_jitter)
    def get_required_permissions(self, sdk_call: str) -> Tuple[str, List[str]]:
        permissions = set()
        try:
            getattr(self.client, sdk_call)()
            return sdk_call, list(permissions)
        except ParamValidationError:
            self._handle_param_validation_error(sdk_call, permissions)
        except ClientError as e:
            self._handle_client_error(e, sdk_call, permissions)
        except Exception as e:
            logger.error(f"Unexpected exception for {sdk_call}: {str(e)}")
        
        return sdk_call, list(permissions)

    def _handle_param_validation_error(self, sdk_call: str, permissions: set):
        try:
            self.iam.simulate_principal_policy(
                PolicySourceArn=f'arn:aws:iam::{self.iam.get_user()["User"]["Arn"].split(":")[4]}:role/{self.role_name}',
                ActionNames=[self.format_iam_action(self.service, sdk_call)],
            )
        except ClientError as sim_error:
            if sim_error.response["Error"]["Code"] == "AccessDenied":
                permissions.add(self.format_iam_action(self.service, sdk_call))

    def _handle_client_error(self, e: ClientError, sdk_call: str, permissions: set):
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]

        if error_code == "AccessDeniedException":
            match = re.search(r"is not authorized to perform: ([\w:]+)", error_message)
            if match:
                permissions.add(match.group(1))
                self._update_role_policy(permissions)
            else:
                logger.warning(f"Couldn't parse permission from error: {error_message}")
        elif error_code == "DryRunOperation":
            return
        else:
            logger.warning(f"ClientError for {sdk_call}: {error_code} - {error_message}")

    @backoff.on_exception(backoff.expo, ClientError, max_tries=MAX_RETRIES, jitter=backoff.full_jitter)
    def _update_role_policy(self, permissions: set):
        try:
            self.iam.put_role_policy(
                RoleName=self.role_name,
                PolicyName="TempPolicy",
                PolicyDocument=json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": list(permissions), "Resource": "*"}
                    ],
                }),
            )
        except ClientError as e:
            logger.error(f"Error updating role policy: {e}")

    def map_service_permissions(self) -> Dict[str, List[str]]:
        self.role_name = self.create_test_role()
        if not self.role_name:
            logger.error("Failed to create test role. Aborting permission mapping.")
            return {}

        service_permissions = {}
        api_to_method = {v: k for k, v in self.client.meta.method_to_api_mapping.items()}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_sdk_call = {
                executor.submit(self.get_required_permissions, api_to_method[api_action]): api_action
                for api_action in self.client.meta.service_model.operation_names
                if api_action in api_to_method
            }

            for future in as_completed(future_to_sdk_call):
                try:
                    sdk_call, permissions = future.result()
                    if permissions:
                        service_permissions[sdk_call] = permissions
                except Exception as e:
                    logger.error(f"Error processing SDK call: {e}")

        self.delete_test_role()
        return service_permissions

    @staticmethod
    def format_iam_action(service: str, action: str) -> str:
        formatted_action = "".join(word.capitalize() for word in action.split("_"))
        return f"{service}:{formatted_action}"

def get_all_aws_services() -> List[str]:
    session = boto3.Session()
    return session.get_available_services()

def map_all_services(region: str = "us-east-1") -> Dict[str, Dict[str, List[str]]]:
    all_services = get_all_aws_services()
    all_permissions = {}

    for service in all_services:
        logger.info(f"Mapping permissions for {service}...")
        mapper = AWSPermissionMapper(service, region)
        permissions = mapper.map_service_permissions()
        if permissions:
            all_permissions[service] = permissions
        logger.info(f"Finished mapping permissions for {service}")

    return all_permissions

def main():
    print("1. Map permissions for a single AWS service")
    print("2. Map permissions for all AWS services")
    choice = input("Enter your choice (1 or 2): ")

    region = "us-east-1"

    if choice == "1":
        service = input("Enter the AWS service name (e.g., 'lambda', 's3'): ")
        mapper = AWSPermissionMapper(service, region)
        permissions = mapper.map_service_permissions()

        if permissions:
            output_file = f"{service}_permissions.json"
            with open(output_file, "w") as f:
                json.dump(permissions, f, indent=2)
            logger.info(f"Permissions mapping for {service} saved to {output_file}")
        else:
            logger.warning(f"No permissions were mapped for {service}. Check your AWS credentials and permissions.")

    elif choice == "2":
        all_permissions = map_all_services(region)

        if all_permissions:
            output_file = "all_aws_permissions.json"
            with open(output_file, "w") as f:
                json.dump(all_permissions, f, indent=2)
            logger.info(f"Permissions mapping for all services saved to {output_file}")
        else:
            logger.warning("No permissions were mapped. Check your AWS credentials and permissions.")

    else:
        logger.error("Invalid choice. Please run the script again and choose 1 or 2.")

if __name__ == "__main__":
    main()