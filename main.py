import boto3
import json
import logging
from botocore.exceptions import ClientError, ParamValidationError
from typing import Dict, List
import re

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class AWSPermissionMapper:
    def __init__(self, service: str, region: str = "us-east-1"):
        self.service = service
        self.region = region
        self.iam = boto3.client("iam")
        self.role_name = f"PermissionMapper-{self.service}"
        self.role_arn = self.create_iam_role()
        self.client = boto3.client(self.service, region_name=self.region)
        self.policy_name = f"PermissionMapper-Policy-{self.service}"
        self.policy_arn = self.create_policy()

    def create_policy(self):
        try:
            response = self.iam.create_policy(
                PolicyName=self.policy_name,
                PolicyDocument=json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Action": ["sts:AssumeRole"], "Resource": "*"}],
                    }
                ),
            )
            policy_arn = response["Policy"]["Arn"]
            self.iam.attach_role_policy(RoleName=self.role_name, PolicyArn=policy_arn)
            return policy_arn
        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityAlreadyExists":
                logger.info(f"IAM policy {self.policy_name} already exists")
                return self.iam.get_policy(
                    PolicyArn=f"arn:aws:iam::{boto3.client('sts').get_caller_identity()['Account']}:policy/{self.policy_name}"
                )["Policy"]["Arn"]
            logger.error(f"Error creating IAM policy: {e}")
            raise

    def create_iam_role(self) -> str:
        try:
            response = self.iam.create_role(
                RoleName=self.role_name,
                AssumeRolePolicyDocument=json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": f"{self.service}.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    }
                ),
            )
            logger.info(f"Created IAM role: {self.role_name}")
            return response["Role"]["Arn"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityAlreadyExists":
                logger.info(f"IAM role {self.role_name} already exists")
                return self.iam.get_role(RoleName=self.role_name)["Role"]["Arn"]
            logger.error(f"Error creating IAM role: {e}")
            raise

    def delete_iam_role_and_policy(self):
        try:
            self.iam.detach_role_policy(RoleName=self.role_name, PolicyArn=self.policy_arn)
            self.iam.delete_policy(PolicyArn=self.policy_arn)
            self.iam.delete_role(RoleName=self.role_name)
            logger.info(f"Deleted IAM role and policy: {self.role_name}")
        except ClientError as e:
            logger.error(f"Error deleting IAM role and policy: {e}")

    def add_permission_to_policy(self, permission: str):
        try:
            policy = self.iam.get_policy_version(
                PolicyArn=self.policy_arn,
                VersionId=self.iam.get_policy(PolicyArn=self.policy_arn)["Policy"]["DefaultVersionId"],
            )["PolicyVersion"]["Document"]

            if not policy["Statement"]:
                policy["Statement"] = []

            policy["Statement"].append({"Effect": "Allow", "Action": permission, "Resource": "*"})

            self.iam.create_policy_version(
                PolicyArn=self.policy_arn, PolicyDocument=json.dumps(policy), SetAsDefault=True
            )
            logger.info(f"Added permission {permission} to policy")
        except ClientError as e:
            logger.error(f"Error adding permission to policy: {e}")

    def attempt_sdk_call(self, sdk_call: str) -> List[str]:
        method = getattr(self.client, sdk_call)
        required_permissions = []

        while True:
            try:
                method()
                break
            except ClientError as e:
                if e.response["Error"]["Code"] == "AccessDenied":
                    error_message = e.response["Error"]["Message"]
                    permission = extract_permission(error_message)

                    if permission:
                        if permission not in required_permissions:
                            required_permissions.append(permission)
                            self.add_permission_to_policy(permission)
                        else:
                            logger.warning(f"Permission {permission} already added but still getting AccessDenied")
                            break
                    else:
                        logger.warning(f"Could not extract permission from error message: {error_message}")
                        break
                elif e.response["Error"]["Code"] == "ParamValidationError":
                    break
                else:
                    logger.warning(f"Unexpected error in {sdk_call}: {str(e)}")
                    break
            except ParamValidationError:
                break
            except Exception as e:
                logger.warning(f"Unexpected error in {sdk_call}: {str(e)}")
                break

        return required_permissions

    def map_service_permissions(self) -> Dict[str, List[str]]:
        service_permissions = {}
        for sdk_call in self.client.meta.method_to_api_mapping.keys():
            permissions = self.attempt_sdk_call(sdk_call)
            if permissions:
                service_permissions[sdk_call] = permissions
        return service_permissions


def extract_permission(error_message: str) -> str:
    # Common patterns for permission extraction
    patterns = [
        r"User: .+ is not authorized to perform: (.+?) on resource",
        r"You are not authorized to perform: (.+?) on",
        r"You are not authorized to perform (.+?)\.",
        r"You do not have permission to (.+?)\. ",
        r"You do not have sufficient permissions to (.+?)\.",
        r"You lack permissions to (.+?);",
        r"The user doesn't have permission to perform the action (.+?) on the",
        r"is not authorized to perform: (.+?) with an explicit deny",
        r"You are not authorized to perform this action\. (.+?) permission",
    ]

    for pattern in patterns:
        match = re.search(pattern, error_message)
        if match:
            return match.group(1).strip()

    # If no pattern matches, log the error and return None
    logger.warning(f"No permission pattern matched for error message: {error_message}")
    return None


def map_service_permissions(service: str, region: str = "us-east-1") -> Dict[str, Dict[str, List[str]]]:
    mapper = AWSPermissionMapper(service, region)
    try:
        permissions = mapper.map_service_permissions()
        return {service: permissions}
    finally:
        mapper.delete_iam_role_and_policy()


def main():
    service = input("Enter the AWS service name (e.g., 'lambda', 's3'): ")
    permissions = map_service_permissions(service, "us-east-1")
    output_file = f"{service}_permissions.json"

    if permissions:
        with open(output_file, "w") as f:
            json.dump(permissions, f, indent=2)
        logger.info(f"Permissions mapping saved to {output_file}")
    else:
        logger.warning("No permissions were mapped. Check your AWS credentials and permissions.")


if __name__ == "__main__":
    main()
