#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IAM Challenges Base Module

This module provides the base classes and implementations for IAM security challenges
in the AWS DevSecOps Game. All challenges focus on read-only operations for security.
"""

import json
from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple

import boto3
from botocore.exceptions import ClientError
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Initialize Rich console for formatted output
console = Console()


class DifficultyLevel(Enum):
    """Enumeration of challenge difficulty levels"""
    BEGINNER = 1
    INTERMEDIATE = 2
    ADVANCED = 3
    EXPERT = 4


class Challenge(ABC):
    """
    Abstract base class for all game challenges.
    
    Provides common structure and methods that all challenges should implement.
    """
    
    def __init__(self, 
                 title: str,
                 description: str,
                 difficulty: DifficultyLevel,
                 points: int,
                 tags: List[str] = None):
        """
        Initialize a new challenge.
        
        Args:
            title: The title of the challenge
            description: A detailed description of the challenge
            difficulty: The difficulty level of the challenge
            points: Points awarded for completing the challenge
            tags: List of tags/categories for the challenge
        """
        self.title = title
        self.description = description
        self.difficulty = difficulty
        self.points = points
        self.tags = tags or []
        self.completed = False
        self.attempts = 0
        self.hints_revealed = 0
        self._hints = []
        
    def add_hint(self, hint: str) -> None:
        """Add a hint to the challenge."""
        self._hints.append(hint)
    
    def get_next_hint(self) -> Optional[str]:
        """Get the next available hint, if any."""
        if self.hints_revealed < len(self._hints):
            hint = self._hints[self.hints_revealed]
            self.hints_revealed += 1
            return hint
        return None
    
    def display_challenge(self) -> None:
        """Display the challenge details in a formatted way."""
        title = f"[bold blue]{self.title}[/bold blue]"
        difficulty_color = {
            DifficultyLevel.BEGINNER: "green",
            DifficultyLevel.INTERMEDIATE: "yellow",
            DifficultyLevel.ADVANCED: "orange",
            DifficultyLevel.EXPERT: "red"
        }.get(self.difficulty, "white")
        
        difficulty_text = f"[{difficulty_color}]{self.difficulty.name}[/{difficulty_color}]"
        points_text = f"[cyan]{self.points} points[/cyan]"
        
        header = f"{title} | {difficulty_text} | {points_text}"
        
        console.print(Panel(
            Text(self.description),
            title=header,
            border_style="blue"
        ))
        
        if self.tags:
            tags_text = " ".join(f"[magenta]#{tag}[/magenta]" for tag in self.tags)
            console.print(f"Tags: {tags_text}\n")
    
    @abstractmethod
    def initialize(self) -> bool:
        """
        Initialize the challenge, setting up any necessary resources or state.
        
        Returns:
            bool: True if initialization successful, False otherwise
        """
        pass
    
    @abstractmethod
    def validate_answer(self, answer: Any) -> Tuple[bool, str]:
        """
        Validate the user's answer to the challenge.
        
        Args:
            answer: The user's answer to validate
            
        Returns:
            Tuple[bool, str]: (is_correct, feedback_message)
        """
        pass
    
    @abstractmethod
    def cleanup(self) -> None:
        """Clean up any resources created for this challenge."""
        pass

    def mark_completed(self) -> None:
        """Mark the challenge as completed."""
        self.completed = True
        console.print(f"[bold green]Challenge completed! You earned {self.points} points.[/bold green]")


class IAMChallenge(Challenge):
    """
    Base class for IAM-specific challenges.
    
    Provides common IAM-related functionality for all IAM challenges.
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Use read-only IAM client by default for security
        self.iam_client = boto3.client('iam')
        self.sts_client = boto3.client('sts')
        
    def check_aws_permissions(self) -> bool:
        """
        Verify that the user has the necessary AWS permissions.
        
        Returns:
            bool: True if user has sufficient read permissions, False otherwise
        """
        try:
            # Safely check permissions using GetCallerIdentity
            # This is a read-only operation that works for all authenticated users
            response = self.sts_client.get_caller_identity()
            console.print(f"[green]Successfully authenticated as: [bold]{response['Arn']}[/bold][/green]")
            return True
        except ClientError as e:
            console.print(f"[bold red]Error checking AWS permissions: {e}[/bold red]")
            return False


class LeastPrivilegeChallenge(IAMChallenge):
    """
    Challenge focusing on IAM least privilege principle.
    
    Tests the user's understanding of IAM permissions and the principle of least privilege.
    """
    
    def __init__(self):
        super().__init__(
            title="Principle of Least Privilege",
            description=(
                "Identify the over-permissive IAM policy from a set of policies. "
                "The principle of least privilege states that users should only have "
                "the minimum permissions necessary to perform their tasks."
            ),
            difficulty=DifficultyLevel.BEGINNER,
            points=100,
            tags=["IAM", "Security", "Permissions"]
        )
        
        # Prepare hints
        self.add_hint("Look for policies that grant '*' permissions on resources.")
        self.add_hint("Consider which services should have limited access scopes.")
        self.add_hint("Review the 'Effect' and 'Action' fields in each policy.")
        
        # Sample IAM policies for the challenge
        self.policies = {
            "Policy1": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::company-data/readonly/*"
                }]
            },
            "Policy2": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                }]
            },
            "Policy3": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["ec2:Describe*", "ec2:Get*"],
                    "Resource": "*"
                }]
            },
            "Policy4": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "dynamodb:Query",
                    "Resource": "arn:aws:dynamodb:*:*:table/users"
                }]
            }
        }
        
        # Solution - Policy2 is overly permissive
        self.solution = "Policy2"
    
    def initialize(self) -> bool:
        """Initialize the challenge by checking AWS permissions."""
        if not self.check_aws_permissions():
            console.print("[bold red]Failed to initialize challenge: insufficient AWS permissions[/bold red]")
            return False
            
        # Display the available policies
        console.print("[bold]Review the following IAM policies:[/bold]\n")
        
        for name, policy in self.policies.items():
            policy_json = json.dumps(policy, indent=2)
            console.print(Panel(
                policy_json,
                title=f"[bold]{name}[/bold]",
                border_style="green"
            ))
            
        console.print("\n[bold yellow]Which policy violates the principle of least privilege?[/bold yellow]")
        return True
    
    def validate_answer(self, answer: str) -> Tuple[bool, str]:
        """
        Validate the user's answer.
        
        Args:
            answer: The name of the policy the user thinks violates least privilege
            
        Returns:
            Tuple[bool, str]: (is_correct, feedback_message)
        """
        self.attempts += 1
        
        if answer == self.solution:
            return True, (
                "Correct! Policy2 grants wildcard permissions (s3:*) on all S3 resources (*). "
                "This violates the principle of least privilege by providing excessive permissions."
            )
        else:
            return False, (
                f"Incorrect. The policy you selected ({answer}) is not the most problematic one. "
                f"Try again and look for overly broad permissions."
            )
    
    def cleanup(self) -> None:
        """
        Clean up any resources created for this challenge.
        
        Since this challenge only uses read-only operations, no cleanup is needed.
        """
        pass
    
    def get_real_world_example(self) -> None:
        """
        Provide a real-world example of least privilege best practices.
        
        This method makes a read-only API call to list IAM policies in the account,
        illustrating how to examine actual AWS resources safely.
        """
        try:
            # This is a read-only operation
            response = self.iam_client.list_policies(
                Scope='AWS',  # Only AWS managed policies
                OnlyAttached=True,  # Only policies attached to users/groups/roles
                MaxItems=5  # Limit to 5 results for demo purposes
            )
            
            console.print("\n[bold]Example AWS Managed Policies with Least Privilege Focus:[/bold]")
            
            for policy in response['Policies']:
                policy_name = policy['PolicyName']
                if "ReadOnly" in policy_name or "View" in policy_name:
                    console.print(f"[green]• {policy_name}[/green] - {policy['Description']}")
            
            console.print("\n[italic]These policies follow least privilege by granting only read access.[/italic]")
            
        except ClientError as e:
            console.print(f"[bold red]Unable to retrieve IAM policies: {e}[/bold red]")
            console.print("[yellow]Note: This requires IAM read permissions.[/yellow]")


# Example of how to instantiate and use the challenge
if __name__ == "__main__":
    challenge = LeastPrivilegeChallenge()
    challenge.display_challenge()
    
    if challenge.initialize():
        # Simulating user input for demonstration
        answer = "Policy2"
        is_correct, feedback = challenge.validate_answer(answer)
        
        if is_correct:
            challenge.mark_completed()
        
        console.print(f"\n[bold]Feedback:[/bold] {feedback}")
        
        # Show a real-world example
        challenge.get_real_world_example()

