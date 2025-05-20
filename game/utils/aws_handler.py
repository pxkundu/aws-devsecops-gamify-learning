"""
AWS operations handler for the AWS DevSecOps Game.

This module provides a safe interface for AWS operations with read-only defaults
and explicit safety checks for any operations that might modify resources.
"""

import os
import json
import logging
import subprocess
from typing import Dict, Any, List, Optional, Tuple, Union
import boto3
from botocore.exceptions import ClientError, ProfileNotFound, NoCredentialsError
from rich.console import Console
from rich.prompt import Confirm

log = logging.getLogger("aws_devsecops_game")
console = Console()

# Define constant lists of read-only and potentially dangerous operations
READ_ONLY_OPERATIONS = {
    # IAM read-only operations
    'iam': ['get', 'list', 'generate-credential-report', 'simulate-principal-policy'],
    # EC2 read-only operations
    'ec2': ['describe', 'get'],
    # S3 read-only operations
    's3': ['get', 'list', 'head'],
    # CloudTrail read-only operations
    'cloudtrail': ['describe', 'get', 'list', 'lookup-events'],
    # Config read-only operations
    'config': ['describe', 'get', 'list'],
    # General services
    'all': ['describe', 'get', 'list', 'generate', 'query']
}

DANGEROUS_OPERATIONS = {
    # Operations that can change or create resources
    'iam': ['create', 'delete', 'update', 'put', 'attach', 'detach', 'add', 'remove'],
    'ec2': ['create', 'delete', 'modify', 'allocate', 'release', 'run', 'terminate', 'start', 'stop'],
    's3': ['create', 'delete', 'put', 'copy', 'move', 'restore'],
    'cloudtrail': ['create', 'delete', 'start', 'stop', 'update'],
    'config': ['delete', 'put', 'start', 'stop'],
    'all': ['create', 'delete', 'update', 'modify', 'put', 'run', 'start', 'stop', 'terminate']
}

class AWSHandler:
    """
    Handler for AWS operations with safety checks to prevent accidental resource modification.
    """
    
    def __init__(self, profile_name: Optional[str] = None, region_name: Optional[str] = None):
        """
        Initialize the AWS handler.
        
        Args:
            profile_name: Optional AWS profile name to use
            region_name: Optional AWS region to use
        """
        self.profile_name = profile_name
        self.region_name = region_name or os.environ.get('AWS_REGION', 'us-east-1')
        self.session = None
        self.account_id = None
        self.read_only_mode = True  # Default to read-only
    
    def create_session(self) -> bool:
        """
        Create an AWS session with the specified profile or default credentials.
        
        Returns:
            True if session creation was successful, False otherwise
        """
        try:
            if self.profile_name:
                self.session = boto3.Session(profile_name=self.profile_name, region_name=self.region_name)
            else:
                self.session = boto3.Session(region_name=self.region_name)
            
            # Test the session by getting the caller identity
            sts_client = self.session.client('sts')
            identity = sts_client.get_caller_identity()
            self.account_id = identity.get('Account')
            
            log.info(f"AWS session created successfully for account {self.account_id}")
            return True
        except (ProfileNotFound, NoCredentialsError) as e:
            log.error(f"Failed to create AWS session: {e}")
            return False
        except Exception as e:
            log.error(f"Unexpected error creating AWS session: {e}")
            return False
    
    def validate_credentials(self) -> bool:
        """
        Validate AWS credentials by checking if we can create a session and call STS.
        
        Returns:
            True if credentials are valid, False otherwise
        """
        return self.create_session()
    
    def is_operation_read_only(self, service: str, operation: str) -> bool:
        """
        Check if an AWS operation is read-only.
        
        Args:
            service: AWS service (e.g., 'ec2', 's3')
            operation: Operation name or prefix (e.g., 'describe', 'get')
            
        Returns:
            True if the operation is read-only, False otherwise
        """
        # Convert to lowercase for case-insensitive comparison
        service = service.lower()
        operation = operation.lower()
        
        # Check if the operation is in the read-only list for the service
        service_read_only = READ_ONLY_OPERATIONS.get(service, [])
        all_read_only = READ_ONLY_OPERATIONS.get('all', [])
        
        # Check if the operation starts with any of the read-only prefixes
        for prefix in service_read_only + all_read_only:
            if operation.startswith(prefix):
                return True
        
        return False
    
    def is_operation_dangerous(self, service: str, operation: str) -> bool:
        """
        Check if an AWS operation is potentially dangerous (could modify resources).
        
        Args:
            service: AWS service (e.g., 'ec2', 's3')
            operation: Operation name or prefix (e.g., 'create', 'delete')
            
        Returns:
            True if the operation is dangerous, False otherwise
        """
        # Convert to lowercase for case-insensitive comparison
        service = service.lower()
        operation = operation.lower()
        
        # Check if the operation is in the dangerous list for the service
        service_dangerous = DANGEROUS_OPERATIONS.get(service, [])
        all_dangerous = DANGEROUS_OPERATIONS.get('all', [])
        
        # Check if the operation starts with any of the dangerous prefixes
        for prefix in service_dangerous + all_dangerous:
            if operation.startswith(prefix):
                return True
        
        return False
    
    def run_aws_cli(self, 
                    command: List[str], 
                    check_read_only: bool = True, 
                    allow_dangerous: bool = False) -> Tuple[bool, str]:
        """
        Run an AWS CLI command with safety checks.
        
        Args:
            command: AWS CLI command as a list of strings (e.g., ['aws', 'ec2', 'describe-instances'])
            check_read_only: Whether to check if the operation is read-only
            allow_dangerous: Whether to allow dangerous operations (with confirmation)
            
        Returns:
            Tuple of (success, output) where success is a boolean and output is the command output
        """
        if len(command) < 3 or command[0] != 'aws':
            log.error("Invalid AWS CLI command format")
            return False, "Invalid AWS CLI command format. Must start with 'aws' followed by a service and operation."
        
        service = command[1]
        operation = command[2]
        
        # Check if the operation is read-only and we're enforcing that constraint
        if check_read_only and self.read_only_mode and not self.is_operation_read_only(service, operation):
            if not allow_dangerous or not Confirm.ask(
                f"[bold red]Warning:[/] The command '{' '.join(command)}' may modify AWS resources. Are you sure you want to proceed?",
                default=False
            ):
                log.warning(f"Blocked non-read-only operation: {' '.join(command)}")
                return False, "Operation blocked: Not a read-only operation. Use allow_dangerous=True to override."
        
        # Additional warning for dangerous operations
        if self.is_operation_dangerous(service, operation):
            if not allow_dangerous or not Confirm.ask(
                f"[bold red]DANGER:[/] The command '{' '.join(command)}' will modify AWS resources. This may incur costs or affect your AWS environment. Are you absolutely sure?",
                default=False
            ):
                log.warning(f"Blocked dangerous operation: {' '.join(command)}")
                return False, "Operation blocked: This is a potentially dangerous operation. Use allow_dangerous=True to override."
        
        # Run the AWS CLI command
        try:
            # Add profile if specified
            if self.profile_name:
                command.extend(['--profile', self.profile_name])
            
            # Add region if specified
            if self.region_name:
                command.extend(['--region', self.region_name])
            
            # Add output format as JSON
            command.extend(['--output', 'json'])
            
            log.info(f"Running AWS CLI command: {' '.join(command)}")
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            
            if result.returncode != 0:
                log.error(f"AWS CLI command failed: {result.stderr}")
                return False, result.stderr
            
            return True, result.stdout
        except Exception as e:
            log.error(f"Error running AWS CLI command: {e}")
            return False, str(e)
    
    def get_iam_user_info(self) -> Dict[str, Any]:
        """
        Get information about the current IAM user.
        
        Returns:
            Dictionary with user information or empty dict if failed
        """
        if not self.session:
            if not self.create_session():
                return {}
        
        try:
            iam = self.session.client('iam')
            return iam.get_user().get('User', {})
        except Exception as e:
            log.error(f"Failed to get IAM user info: {e}")
            return {}
    
    def get_account_info(self) -> Dict[str, Any]:
        """
        Get basic information about the AWS account.
        
        Returns:
            Dictionary with account information
        """
        info = {
            'account_id': self.account_id,
            'region': self.region_name,
        }
        
        # Add user info if possible
        user_info = self.get_iam_user_info()
        if user_info:
            info['user_name'] = user_info.get('UserName')
            info['user_id'] = user_info.get('UserId')
            info['user_arn'] = user_info.get('Arn')
        
        return info
    
    def check_security_group_rules(self, group_id: str) -> Dict[str, Any]:
        """
        Analyze a security group for potential security issues.
        
        Args:
            group_id: The security group ID to analyze
            
        Returns:
            Dictionary with analysis results
        """
        if not self.session:
            if not self.create_session():
                return {'error': 'No valid AWS session'}
        
        try:
            ec2 = self.session.client('ec2')
            response = ec2.describe_security_groups(GroupIds=[group_id])
            
            if not response.get('SecurityGroups'):
                return {'error': f'No security group found with ID {group_id}'}
            
            group = response['SecurityGroups'][0]
            issues = []
            
            # Check inbound rules for common issues
            for rule in group.get('IpPermissions', []):
                # Check for wide open rules (0.0.0.0/0)
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        port_info = ""
                        if rule.get('FromPort') == rule.get('ToPort'):
                            port_info = f"port {rule.get('FromPort')}"
                        elif rule.get('FromPort') is not None and rule.get('ToPort') is not None:
                            port_info = f"ports {rule.get('FromPort')}-{rule.get('ToPort')}"
                            
                        issues.append({
                            'severity': 'HIGH',
                            'issue_type': 'OPEN_TO_WORLD',
                            'description': f"Security group allows access from anywhere (0.0.0.0/0) on {port_info} for protocol {rule.get('IpProtocol')}",
                            'recommendation': 'Restrict access to specific IP ranges'
                        })
            
            return {
                'group_id': group_id,
                'group_name': group.get('GroupName'),
                'description': group.get('Description'),
                'issues': issues,
                'rule_count': len(group.get('IpPermissions', [])),
                'vpc_id': group.get('VpcId')
            }
            
        except Exception as e:
            log.error(f"Error analyzing security group {group_id}: {e}")
            return {'error': str(e)}
    
    def analyze_iam_user_permissions(self, user_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze an IAM user's permissions for security best practices.
        
        Args:
            user_name: Optional username to analyze, uses current user if None
            
        Returns:
            Dictionary with analysis results
        """
        if not self.session:
            if not self.create_session():
                return {'error': 'No valid AWS session'}
                
        try:
            iam = self.session.client('iam')
            
            if user_name is None:
                # Get the current user
                caller = self.session.client('sts').get_caller_identity()
                user_arn = caller.get('Arn', '')
                if ':user/' in user_arn:
                    user_name = user_arn.split('/')[-1]
                else:
                    return {'error': 'Current credentials are not for an IAM user'}
            
            # Get user details
            user = iam.get_user(UserName=user_name)['User']
            
            # Get user policies
            attached_policies = iam.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
            inline_policies = iam.list_user_policies(UserName=user_name)['PolicyNames']
            
            # Get group memberships and their policies
            groups = iam.list_groups_for_user(UserName=user_name)['Groups']
            group_policies = []
            
            for group in groups:
                group_name = group['GroupName']
                group_attached = iam.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
                group_inline = iam.list_group_policies(GroupName=group_name)['PolicyNames']
                
                group_policies.append({
                    'group_name': group_name,
                    'attached_policies': group_attached,
                    'inline_policies': group_inline
                })
            
            # Look for admin or full access policies
            admin_policies = []
            for policy in attached_policies:
                if 'admin' in policy['PolicyName'].lower() or 'full' in policy['PolicyName'].lower():
                    admin_policies.append(policy['PolicyName'])
            
            # Check for security issues
            issues = []
            
            # Check for admin policies
            if admin_policies:
                issues.append({
                    'severity': 'HIGH',
                    'issue_type': 'ADMIN_POLICY',
                    'description': f"User has admin policies attached: {', '.join(admin_policies)}",
                    'recommendation': 'Apply least privilege principle - remove admin policies and grant only necessary permissions'
                })
            
            # Check console access without MFA
            if user.get('PasswordLastUsed') and not iam.list_mfa_devices(UserName=user_name)['MFADevices']:
                issues.append({
                    'severity': 'HIGH',
                    'issue_type': 'NO_MFA',
                    'description': 'User has console access but no MFA device configured',
                    'recommendation': 'Configure MFA for all users with console access'
                })
            
            return {
                'user_name': user_name,
                'user_id': user.get('UserId'),
                'user_arn': user.get('Arn'),
                'create_date': user.get('CreateDate').isoformat() if user.get('CreateDate') else None,
                'password_last_used': user.get('PasswordLastUsed').isoformat() if user.get('PasswordLastUsed') else None,
                'has_console_access': user.get('PasswordLastUsed') is not None,
                'attached_policies': [p['PolicyName'] for p in attached_policies],
                'inline_policies': inline_policies,
                'groups': [g['GroupName'] for g in groups],
                'group_policies': group_policies,
                'admin_policies': admin_policies,
                'issues': issues
            }
            
        except Exception as e:
            log.error(f"Error analyzing IAM user permissions: {e}")
            return {'error': str(e)}
    
    def check_password_policy(self) -> Dict[str, Any]:
        """
        Check the IAM password policy for security best practices.
        
        Returns:
            Dictionary with password policy analysis results
        """
        if not self.session:
            if not self.create_session():
                return {'error': 'No valid AWS session'}
        
        try:
            iam = self.session.client('iam')
            
            try:
                policy = iam.get_account_password_policy()['PasswordPolicy']
            except ClientError as e:
                if 'NoSuchEntity' in str(e):
                    return {
                        'exists': False,
                        'issues': [{
                            'severity': 'HIGH',
                            'issue_type': 'NO_PASSWORD_POLICY',
                            'description': 'No password policy is configured for the account',
                            'recommendation': 'Configure a strong password policy'
                        }]
                    }
                raise
            
            issues = []
            
            # Check minimum length
            if policy.get('MinimumPasswordLength', 0) < 14:
                issues.append({
                    'severity': 'MEDIUM',
                    'issue_type': 'WEAK_PASSWORD_LENGTH',
                    'description': f"Password minimum length is only {policy.get('MinimumPasswordLength')} characters",
                    'recommendation': 'Require passwords to be at least 14 characters long'
                })
            
            # Check password reuse
            if not policy.get('PasswordReusePrevention'):
                issues.append({
                    'severity': 'MEDIUM',
                    'issue_type': 'PASSWORD_REUSE_ALLOWED',
                    'description': 'Password reuse prevention is not enabled',
                    'recommendation': 'Prevent reuse of previous passwords (recommended: 24)'
                })
            elif policy.get('PasswordReusePrevention', 0) < 24:
                issues.append({
                    'severity': 'LOW',
                    'issue_type': 'WEAK_PASSWORD_REUSE_PREVENTION',
                    'description': f"Password reuse prevention is only set to {policy.get('PasswordReusePrevention')} previous passwords",
                    'recommendation': 'Increase password reuse prevention to 24 previous passwords'
                })
            
            # Check password expiration
            if not policy.get('ExpirePasswords', True):
                issues.append({
                    'severity': 'MEDIUM',
                    'issue_type': 'NO_PASSWORD_EXPIRATION',
                    'description': 'Password expiration is not enabled',
                    'recommendation': 'Enable password expiration'
                })
            elif policy.get('MaxPasswordAge', 0) > 90:
                issues.append({
                    'severity': 'LOW',
                    'issue_type': 'LONG_PASSWORD_EXPIRATION',
                    'description': f"Password expiration is set to {policy.get('MaxPasswordAge')} days",
                    'recommendation': 'Reduce password expiration to 90 days or less'
                })
            
            return {
                'exists': True,
                'policy': policy,
                'issues': issues
            }
            
        except Exception as e:
            log.error(f"Error checking password policy: {e}")
            return {'error': str(e)}
    
    def check_s3_bucket_security(self, bucket_name: str) -> Dict[str, Any]:
        """
        Analyze an S3 bucket for security best practices.
        
        Args:
            bucket_name: The name of the S3 bucket to analyze
            
        Returns:
            Dictionary with bucket security analysis results
        """
        if not self.session:
            if not self.create_session():
                return {'error': 'No valid AWS session'}
        
        try:
            s3 = self.session.client('s3')
            issues = []
            
            # Check bucket ACL
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        issues.append({
                            'severity': 'HIGH',
                            'issue_type': 'PUBLIC_ACL',
                            'description': f"Bucket has public access via ACL: {grant.get('Permission')} permission for AllUsers",
                            'recommendation': 'Remove public access permissions from bucket ACL'
                        })
                    elif grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                        issues.append({
                            'severity': 'HIGH',
                            'issue_type': 'AUTHENTICATED_USERS_ACL',
                            'description': f"Bucket grants {grant.get('Permission')} permission to all AWS authenticated users",
                            'recommendation': 'Remove authenticated users group from bucket ACL'
                        })
            except Exception as e:
                log.warning(f"Could not check bucket ACL: {e}")
                issues.append({
                    'severity': 'MEDIUM',
                    'issue_type': 'ACL_CHECK_FAILED',
                    'description': f"Could not check bucket ACL: {e}",
                    'recommendation': 'Ensure you have proper permissions to check bucket ACLs'
                })
            
            # Check bucket policy
            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                policy_str = policy.get('Policy', '')
                
                # Simple check for public access in policy (this is a basic heuristic)
                if '"Principal": "*"' in policy_str or '"Principal":"*"' in policy_str:
                    issues.append({
                        'severity': 'HIGH',
                        'issue_type': 'PUBLIC_POLICY',
                        'description': 'Bucket policy contains a public (*) principal',
                        'recommendation': 'Review bucket policy and remove public access'
                    })
            except ClientError as e:
                if 'NoSuchBucketPolicy' in str(e):
                    # No bucket policy exists, which is fine
                    pass
                else:
                    log.warning(f"Could not check bucket policy: {e}")
                    issues.append({
                        'severity': 'LOW',
                        'issue_type': 'POLICY_CHECK_FAILED',
                        'description': f"Could not check bucket policy: {e}",
                        'recommendation': 'Ensure you have proper permissions to check bucket policies'
                    })
            
            # Check encryption
            try:
                encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                # If we get here, encryption is enabled
            except ClientError as e:
                if 'ServerSideEncryptionConfigurationNotFoundError' in str(e):
                    issues.append({
                        'severity': 'HIGH',
                        'issue_type': 'NO_ENCRYPTION',
                        'description': 'Bucket does not have default encryption enabled',
                        'recommendation': 'Enable default encryption for the bucket'
                    })
                else:
                    log.warning(f"Could not check bucket encryption: {e}")
                    issues.append({
                        'severity': 'LOW',
                        'issue_type': 'ENCRYPTION_CHECK_FAILED',
                        'description': f"Could not check bucket encryption: {e}",
                        'recommendation': 'Ensure you have proper permissions to check bucket encryption'
                    })
            
            # Check public access block settings
            try:
                public_access_block = s3.get_public_access_block(Bucket=bucket_name)
                config = public_access_block.get('PublicAccessBlockConfiguration', {})
                
                for setting, enabled in config.items():
                    if not enabled:
                        issues.append({
                            'severity': 'MEDIUM',
                            'issue_type': f"{setting.upper()}_DISABLED",
                            'description': f"Public access block setting {setting} is disabled",
                            'recommendation': 'Enable all public access block settings'
                        })
                
            except ClientError as e:
                if 'NoSuchPublicAccessBlockConfiguration' in str(e):
                    issues.append({
                        'severity': 'HIGH',
                        'issue_type': 'NO_PUBLIC_ACCESS_BLOCK',
                        'description': 'Bucket does not have public access block configuration',
                        'recommendation': 'Configure public access block for the bucket'
                    })
                else:
                    log.warning(f"Could not check bucket public access block: {e}")
                    issues.append({
                        'severity': 'LOW',
                        'issue_type': 'PUBLIC_ACCESS_BLOCK_CHECK_FAILED',
                        'description': f"Could not check bucket public access block: {e}",
                        'recommendation': 'Ensure you have proper permissions to check public access block configuration'
                    })
            
            return {
                'bucket_name': bucket_name,
                'issues': issues
            }
            
        except Exception as e:
            log.error(f"Error checking S3 bucket security: {e}")
            return {'error': str(e)}
    
    def check_cloudtrail_configuration(self) -> Dict[str, Any]:
        """
        Check CloudTrail configuration for security best practices.
        
        Returns:
            Dictionary with CloudTrail analysis results
        """
        if not self.session:
            if not self.create_session():
                return {'error': 'No valid AWS session'}
        
        try:
            cloudtrail = self.session.client('cloudtrail')
            
            # Get all trails
            trails = cloudtrail.list_trails()['Trails']
            
            if not trails:
                return {
                    'trails': [],
                    'issues': [{
                        'severity': 'HIGH',
                        'issue_type': 'NO_CLOUDTRAIL',
                        'description': 'No CloudTrail trails configured',
                        'recommendation': 'Create a CloudTrail trail to log API activity'
                    }]
                }
            
            trail_details = []
            issues = []
            multi_region_trail_exists = False
            
            for trail in trails:
                trail_arn = trail['TrailARN']
                trail_name = trail.get('Name', 'Unknown')
                
                # Get trail details
                try:
                    details = cloudtrail.get_trail(Name=trail_arn)['Trail']
                    status = cloudtrail.get_trail_status(Name=trail_arn)
                    
                    is_multi_region = details.get('IsMultiRegionTrail', False)
                    is_logging = status.get('IsLogging', False)
                    log_file_validation = details.get('LogFileValidationEnabled', False)
                    
                    if is_multi_region:
                        multi_region_trail_exists = True
                    
                    # Check for security issues
                    if not is_logging:
                        issues.append({
                            'severity': 'HIGH',
                            'issue_type': 'TRAIL_NOT_LOGGING',
                            'description': f"Trail '{trail_name}' is not currently logging",
                            'recommendation': 'Enable logging for the trail'
                        })
                    
                    if not log_file_validation:
                        issues.append({
                            'severity': 'MEDIUM',
                            'issue_type': 'LOG_FILE_VALIDATION_DISABLED',
                            'description': f"Trail '{trail_name}' does not have log file validation enabled",
                            'recommendation': 'Enable log file validation to detect log tampering'
                        })
                    
                    trail_details.append({
                        'name': trail_name,
                        'arn': trail_arn,
                        'is_multi_region': is_multi_region,
                        'is_logging': is_logging,
                        'log_file_validation': log_file_validation,
                        's3_bucket': details.get('S3BucketName'),
                        'log_group_arn': details.get('CloudWatchLogsLogGroupArn')
                    })
                    
                except Exception as e:
                    log.warning(f"Could not get details for trail {trail_arn}: {e}")
                    issues.append({
                        'severity': 'LOW',
                        'issue_type': 'TRAIL_DETAILS_FAILED',
                        'description': f"Could not get details for trail '{trail_name}': {e}",
                        'recommendation': 'Ensure you have proper permissions to access trail details'
                    })
            
            if not multi_region_trail_exists:
                issues.append({
                    'severity': 'MEDIUM',
                    'issue_type': 'NO_MULTI_REGION_TRAIL',
                    'description': 'No multi-region CloudTrail trail exists',
                    'recommendation': 'Create a multi-region trail to log events from all AWS regions'
                })
            
            return {
                'trails': trail_details,
                'issues': issues,
                'multi_region_trail_exists': multi_region_trail_exists
            }
            
        except Exception as e:
            log.error(f"Error checking CloudTrail configuration: {e}")
            return {'error': str(e)}
    
    def check_container_security(self, image_name: str) -> Dict[str, Any]:
        """
        Analyze a Docker container image for security best practices.
        
        Args:
            image_name: Name of the Docker image to analyze (e.g., 'nginx:latest')
            
        Returns:
            Dictionary with container security analysis results
        """
        issues = []
        try:
            # Check if the Docker CLI is available
            result = subprocess.run(['docker', '--version'], capture_output=True, text=True, check=False)
            if result.returncode != 0:
                return {
                    'error': 'Docker CLI not available. Please install Docker to run container security checks.'
                }
            
            # Check if the image exists locally
            result = subprocess.run(['docker', 'image', 'inspect', image_name], 
                                   capture_output=True, text=True, check=False)
            
            if result.returncode != 0:
                # Image doesn't exist locally - this is just a warning
                issues.append({
                    'severity': 'LOW',
                    'issue_type': 'IMAGE_NOT_FOUND',
                    'description': f"Image '{image_name}' not found locally",
                    'recommendation': 'Pull the image with `docker pull {image_name}` before analysis'
                })
                return {
                    'image_name': image_name,
                    'exists_locally': False,
                    'issues': issues
                }
            
            # Parse image details
            try:
                image_details = json.loads(result.stdout)
                
                # Check for running as root
                if len(image_details) > 0:
                    config = image_details[0].get('Config', {})
                    user = config.get('User', '')
                    
                    if not user or user == 'root':
                        issues.append({
                            'severity': 'HIGH',
                            'issue_type': 'RUNS_AS_ROOT',
                            'description': 'Container runs as root user',
                            'recommendation': 'Use a non-root user in the container for better security'
                        })
                    
                    # Check for exposed ports
                    exposed_ports = config.get('ExposedPorts', {})
                    if exposed_ports:
                        issues.append({
                            'severity': 'MEDIUM',
                            'issue_type': 'EXPOSED_PORTS',
                            'description': f"Container exposes ports: {', '.join(exposed_ports.keys())}",
                            'recommendation': 'Only expose necessary ports and ensure they are secured'
                        })
            
            except json.JSONDecodeError:
                issues.append({
                    'severity': 'LOW',
                    'issue_type': 'JSON_PARSE_ERROR',
                    'description': 'Could not parse image details',
                    'recommendation': 'Ensure the Docker CLI is working correctly'
                })
            
            return {
                'image_name': image_name,
                'exists_locally': True,
                'issues': issues
            }
            
        except Exception as e:
            log.error(f"Error analyzing container security: {e}")
            return {'error': str(e)}
    
    def check_aws_config_status(self) -> Dict[str, Any]:
        """
        Check if AWS Config is enabled and properly configured.
        
        Returns:
            Dictionary with AWS Config analysis results
        """
        if not self.session:
            if not self.create_session():
                return {'error': 'No valid AWS session'}
        
        try:
            config = self.session.client('config')
            issues = []
            
            # Check if Config is recording
            try:
                recorders = config.describe_configuration_recorders()['ConfigurationRecorders']
                if not recorders:
                    issues.append({
                        'severity': 'HIGH',
                        'issue_type': 'NO_CONFIG_RECORDER',
                        'description': 'AWS Config recorder is not set up',
                        'recommendation': 'Enable AWS Config to track resource configurations and changes'
                    })
                else:
                    # Check if all recorders are enabled
                    for recorder in recorders:
                        recorder_name = recorder['name']
                        recorder_status = config.describe_configuration_recorder_status(
                            ConfigurationRecorderName=recorder_name
                        )
                        
                        if not recorder_status.get('recording', False):
                            issues.append({
                                'severity': 'HIGH',
                                'issue_type': 'CONFIG_RECORDER_DISABLED',
                                'description': f"AWS Config recorder '{recorder_name}' is not recording",
                                'recommendation': 'Enable the Config recorder to track resource configurations'
                            })
                        
                        # Check if the recorder is recording all resources
                        all_resource_types = recorder.get('recordingGroup', {}).get('allSupported', False)
                        if not all_resource_types:
                            issues.append({
                                'severity': 'MEDIUM',
                                'issue_type': 'PARTIAL_RESOURCE_RECORDING',
                                'description': f"AWS Config recorder '{recorder_name}' is not recording all resource types",
                                'recommendation': 'Configure the recorder to track all supported resource types'
                            })
            
            except Exception as e:
                log.warning(f"Could not check Config recorders: {e}")
                issues.append({
                    'severity': 'LOW',
                    'issue_type': 'CONFIG_CHECK_FAILED',
                    'description': f"Could not check Config recorder status: {e}",
                    'recommendation': 'Ensure you have proper permissions to check AWS Config'
                })
            
            # Check delivery channels
            try:
                delivery_channels = config.describe_delivery_channels()['DeliveryChannels']
                if not delivery_channels:
                    issues.append({
                        'severity': 'HIGH',
                        'issue_type': 'NO_DELIVERY_CHANNEL',
                        'description': 'No AWS Config delivery channel configured',
                        'recommendation': 'Set up a delivery channel to store configuration data'
                    })
            except Exception as e:
                log.warning(f"Could not check Config delivery channels: {e}")
                issues.append({
                    'severity': 'LOW',
                    'issue_type': 'DELIVERY_CHANNEL_CHECK_FAILED',
                    'description': f"Could not check Config delivery channels: {e}",
                    'recommendation': 'Ensure you have proper permissions to check AWS Config'
                })
            
            return {
                'issues': issues
            }
            
        except Exception as e:
            log.error(f"Error checking AWS Config status: {e}")
            return {'error': str(e)}
    
    def check_vpc_flow_logs(self, vpc_id: str) -> Dict[str, Any]:
        """
        Check if VPC Flow Logs are enabled for a VPC.
        
        Args:
            vpc_id: The VPC ID to check
            
        Returns:
            Dictionary with VPC Flow Logs analysis results
        """
        if not self.session:
            if not self.create_session():
                return {'error': 'No valid AWS session'}
        
        try:
            ec2 = self.session.client('ec2')
            
            # Verify the VPC exists
            try:
                vpc_response = ec2.describe_vpcs(VpcIds=[vpc_id])
                if not vpc_response.get('Vpcs'):
                    return {'error': f'VPC {vpc_id} not found'}
            except Exception as e:
                log.error(f"VPC {vpc_id} not found or access denied: {e}")
                return {'error': f'VPC {vpc_id} not found or access denied: {e}'}
            
            # Check flow logs
            flow_logs_response = ec2.describe_flow_logs(
                Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
            )
            
            flow_logs = flow_logs_response.get('FlowLogs', [])
            
            if not flow_logs:
                return {
                    'vpc_id': vpc_id,
                    'flow_logs_enabled': False,
                    'issues': [{
                        'severity': 'HIGH',
                        'issue_type': 'NO_FLOW_LOGS',
                        'description': f"VPC {vpc_id} does not have flow logs enabled",
                        'recommendation': 'Enable VPC Flow Logs to monitor and analyze network traffic'
                    }]
                }
            
            # Check the status of each flow log
            issues = []
            active_logs = []
            
            for log in flow_logs:
                log_id = log.get('FlowLogId')
                log_status = log.get('FlowLogStatus')
                
                if log_status == 'ACTIVE':
                    active_logs.append(log_id)
                else:
                    issues.append({
                        'severity': 'MEDIUM',
                        'issue_type': 'INACTIVE_FLOW_LOG',
                        'description': f"Flow log {log_id} is not active (status: {log_status})",
                        'recommendation': 'Check the flow log configuration and ensure it is active'
                    })
            
            if not active_logs:
                issues.append({
                    'severity': 'HIGH',
                    'issue_type': 'NO_ACTIVE_FLOW_LOGS',
                    'description': f"VPC {vpc_id} has flow logs configured, but none are active",
                    'recommendation': 'Ensure at least one flow log is active for the VPC'
                })
            
            return {
                'vpc_id': vpc_id,
                'flow_logs_enabled': len(active_logs) > 0,
                'active_logs': active_logs,
                'all_logs': [log.get('FlowLogId') for log in flow_logs],
                'issues': issues
            }
            
        except Exception as e:
            log.error(f"Error checking VPC flow logs: {e}")
            return {'error': str(e)}

