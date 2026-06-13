"""
Users API v2.0 - Modular Routes Package

This package contains routes for /api/v2/users/*
split into thematic modules.
"""

import logging
from flask import Blueprint

logger = logging.getLogger(__name__)

# Create the blueprint here
bp = Blueprint('users_v2', __name__)

# Import password policy (always available since v2.160)
from security.password_policy import validate_password, get_password_strength, get_policy_requirements


def validate_password_strength(password, username=None):
    """
    SECURITY: Validate password meets security requirements
    Returns (is_valid, error_message)
    """
    is_valid, errors = validate_password(password, username=username)
    if not is_valid:
        first = errors[0] if errors else {'message': 'Invalid password'}
        return False, first.get('message', 'Invalid password') if isinstance(first, dict) else str(first)
    return True, None


# Note: Route modules are imported in api/v2/__init__.py to register routes
# This avoids circular import issues
