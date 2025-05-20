#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IAM Challenges Loader

This module loads and manages IAM-related challenges.
"""

from typing import Dict, Optional
import boto3
from .least_privilege import LeastPrivilegeChallenge

class IAMChallengeLoader:
    """Loads and manages IAM challenges."""
    
    def __init__(self, aws_session: Optional[boto3.Session] = None):
        """
        Initialize the challenge loader.
        
        Args:
            aws_session: Optional AWS session for challenges that use AWS
        """
        self.aws_session = aws_session
        self.challenges: Dict[str, any] = {
            'iam_least_privilege': LeastPrivilegeChallenge(aws_session)
        }
    
    def get_challenge(self, challenge_id: str):
        """
        Get a challenge instance by ID.
        
        Args:
            challenge_id: ID of the challenge to get
            
        Returns:
            Challenge instance or None if not found
        """
        return self.challenges.get(challenge_id)
    
    def list_challenges(self):
        """
        List all available challenges.
        
        Returns:
            List of challenge IDs
        """
        return list(self.challenges.keys())

