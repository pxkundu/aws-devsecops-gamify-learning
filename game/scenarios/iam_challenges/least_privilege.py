#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IAM Least Privilege Challenge

This module implements the first IAM challenge focusing on the principle of least privilege.
It provides both offline learning using example policies and online validation with AWS when
credentials are available.
"""

import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import boto3
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.prompt import Prompt, Confirm

# Initialize Rich console
console = Console()

# Example policies for offline learning
EXAMPLE_POLICIES = {
    "overly_permissive": {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }]
    },
    "more_specific": {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::my-bucket",
                "arn:aws:s3:::my-bucket/*"
            ]
        }]
    },
    "least_privilege": {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "s3:GetObject"
            ],
            "Resource": "arn:aws:s3:::my-bucket/readonly/*"
        }]
    }
}

@dataclass
class PolicyAnalysisTask:
    """Represents a policy analysis task in the challenge."""
    policy: Dict
    question: str
    correct_answer: List[str]
    explanation: str
    hints: List[str]

class LeastPrivilegeChallenge:
    """
    Challenge implementation for learning IAM least privilege principle.
    
    This challenge teaches:
    1. Understanding overly permissive policies
    2. Identifying unnecessary permissions
    3. Writing least privilege policies
    """
    
    def __init__(self, aws_session: Optional[boto3.Session] = None):
        """Initialize the challenge with optional AWS session."""
        self.aws_session = aws_session
        
        # Required Challenge attributes
        self.id = 'iam_least_privilege'
        self.name = 'Principle of Least Privilege'
        self.category = 'IAM'
        self.difficulty = 'Beginner'
        self.points = 100
        self.description = ('Learn about the AWS IAM principle of least privilege by analyzing '
                          'and identifying secure vs. insecure IAM policies.')
        self.aws_permissions = [
            'iam:ListPolicies',
            'iam:GetPolicy',
            'iam:GetPolicyVersion',
            'sts:GetCallerIdentity'
        ]
        self.learning_objectives = [
            'Understand the principle of least privilege',
            'Identify overly permissive IAM policies',
            'Learn AWS managed policies best practices'
        ]
        self.prerequisites = []
        self.estimated_time = '15-20 minutes'
        
        # Challenge state
        self.completed = False
        self.attempts = 0
        self.completion_date = None
        self.score = 0
        self.max_score = 100
        
    def start(self) -> bool:
        """
        Start the challenge.
        
        Returns:
            bool: True if challenge was completed successfully
        """
        console.print(Panel(
            "[bold]Welcome to the IAM Least Privilege Challenge![/bold]\n\n"
            "In this challenge, you'll learn about the AWS IAM principle of least privilege.\n"
            "We'll examine common IAM policy mistakes and learn how to fix them.",
            title="[blue]Challenge: Principle of Least Privilege[/blue]",
            border_style="blue"
        ))
        
        # Part 1: Understanding overly permissive policies
        if not self._complete_policy_analysis():
            return False
            
        # Part 2: Identifying necessary permissions
        if not self._complete_permission_identification():
            return False
            
        # Part 3: Writing least privilege policy (if AWS available)
        if self.aws_session:
            if not self._complete_aws_policy_creation():
                return False
        
        # Challenge completed!
        self.completed = True
        return True
        
    def _complete_policy_analysis(self) -> bool:
        """Complete the policy analysis section."""
        console.print("\n[bold]Part 1: Analyzing IAM Policies[/bold]")
        console.print("Let's examine some IAM policies and identify security issues.\n")
        
        tasks = [
            PolicyAnalysisTask(
                policy=EXAMPLE_POLICIES["overly_permissive"],
                question="What security issues do you see in this policy?",
                correct_answer=[
                    "all", "everything", "overly permissive", "too broad",
                    "unrestricted", "full access", "admin"
                ],
                explanation=(
                    "This policy grants unrestricted access (*) to all AWS services and resources. "
                    "This violates the principle of least privilege and should be avoided."
                ),
                hints=[
                    "Look at the Action and Resource fields",
                    "Consider what '*' means in a policy",
                    "Think about what permissions are actually needed"
                ]
            ),
            PolicyAnalysisTask(
                policy=EXAMPLE_POLICIES["more_specific"],
                question="Is this policy following the principle of least privilege? Why or why not?",
                correct_answer=[
                    "write", "put", "modify", "broad", "multiple", "actions"
                ],
                explanation=(
                    "While this policy is more specific than the first, it still grants write "
                    "access (PutObject) when only read access might be needed."
                ),
                hints=[
                    "Consider if all these S3 actions are necessary",
                    "Look for write/modify permissions",
                    "Think about separation of read and write access"
                ]
            )
        ]
        
        for i, task in enumerate(tasks, 1):
            console.print(f"\n[bold]Policy Example {i}:[/bold]")
            syntax = Syntax(json.dumps(task.policy, indent=2), "json", theme="monokai")
            console.print(syntax)
            
            # Show question and get answer
            console.print(f"\n[yellow]{task.question}[/yellow]")
            attempts = 0
            max_attempts = 3
            
            while attempts < max_attempts:
                answer = Prompt.ask("[bold]Your answer[/bold]").strip().lower()
                
                if any(keyword in answer for keyword in task.correct_answer):
                    console.print(f"\n[green]✓ Correct![/green]")
                    console.print(task.explanation)
                    self.score += 20
                    break
                else:
                    attempts += 1
                    if attempts < max_attempts:
                        console.print(f"\n[yellow]Not quite. Here's a hint:[/yellow]")
                        console.print(task.hints[attempts - 1])
                    else:
                        console.print(f"\n[red]✗ The correct answer was:[/red]")
                        console.print(task.explanation)
                        return False
        
        return True
        
    def _complete_permission_identification(self) -> bool:
        """Complete the permission identification section."""
        console.print("\n[bold]Part 2: Identifying Necessary Permissions[/bold]")
        console.print(
            "Given a specific task, identify only the permissions that are truly needed.\n"
        )
        
        scenarios = [
            {
                "description": (
                    "An application needs to read files from a specific S3 bucket directory "
                    "called 'reports/'. What permissions should it have?"
                ),
                "correct": ["s3:GetObject", "reports", "specific", "read"],
                "explanation": (
                    "The application only needs s3:GetObject permission on the specific "
                    "resource: arn:aws:s3:::bucket-name/reports/*"
                )
            },
            {
                "description": (
                    "A monitoring script needs to check if EC2 instances are running. "
                    "What permissions should it have?"
                ),
                "correct": ["ec2:DescribeInstances", "describe", "read", "view"],
                "explanation": (
                    "Only ec2:DescribeInstances is needed. This is a read-only action "
                    "that doesn't modify any resources."
                )
            }
        ]
        
        for i, scenario in enumerate(scenarios, 1):
            console.print(f"\n[bold]Scenario {i}:[/bold]")
            console.print(scenario["description"])
            
            attempts = 0
            max_attempts = 2
            
            while attempts < max_attempts:
                answer = Prompt.ask(
                    "[bold]What specific permissions would you grant?[/bold]"
                ).strip().lower()
                
                if any(keyword in answer for keyword in scenario["correct"]):
                    console.print(f"\n[green]✓ Correct![/green]")
                    console.print(scenario["explanation"])
                    self.score += 30
                    break
                else:
                    attempts += 1
                    if attempts < max_attempts:
                        console.print(
                            f"\n[yellow]Think about the minimal permissions needed "
                            f"for this specific task.[/yellow]"
                        )
                    else:
                        console.print(f"\n[red]✗ The correct approach was:[/red]")
                        console.print(scenario["explanation"])
                        return False
        
        return True
        
    def _complete_aws_policy_creation(self) -> bool:
        """
        Complete the AWS policy creation section.
        Only runs if AWS credentials are available.
        """
        console.print("\n[bold]Part 3: Creating Least Privilege Policies[/bold]")
        console.print(
            "Now let's practice creating a least privilege policy in your AWS account.\n"
        )
        
        try:
            iam = self.aws_session.client('iam')
            
            # Get existing policies as examples
            response = iam.list_policies(Scope='AWS', OnlyAttached=True, MaxItems=5)
            
            console.print("[bold]Here are some AWS managed policies for reference:[/bold]")
            for policy in response['Policies']:
                console.print(f"• {policy['PolicyName']}")
            
            # Show a practical example
            example_policy = EXAMPLE_POLICIES["least_privilege"]
            console.print("\n[bold]Here's a least privilege policy example:[/bold]")
            syntax = Syntax(json.dumps(example_policy, indent=2), "json", theme="monokai")
            console.print(syntax)
            
            # Ask user to identify least privilege aspects
            console.print(
                "\n[yellow]What makes this policy follow the principle of "
                "least privilege?[/yellow]"
            )
            
            answer = Prompt.ask("[bold]Your answer[/bold]").strip().lower()
            keywords = ["specific", "single", "read", "getobject", "readonly"]
            
            if any(keyword in answer for keyword in keywords):
                console.print(
                    "\n[green]✓ Correct! This policy grants only the specific read "
                    "access needed, limited to a specific path.[/green]"
                )
                self.score += 20
                return True
            else:
                console.print(
                    "\n[red]✗ The policy follows least privilege by:[/red]\n"
                    "1. Granting only GetObject (read) permission\n"
                    "2. Limiting access to a specific bucket and path\n"
                    "3. Not including any unnecessary permissions"
                )
                return False
                
        except Exception as e:
            console.print(
                f"\n[yellow]Could not connect to AWS. Skipping AWS policy "
                f"creation section: {e}[/yellow]"
            )
            return True  # Still allow completion without AWS
            
    def get_score(self) -> Tuple[int, int]:
        """
        Get the current score and maximum possible score.
        
        Returns:
            Tuple containing (current_score, max_score)
        """
        return (self.score, self.max_score)

