"""
Users Password Policy Routes
"""

from . import bp
from flask import request
from utils.response import success_response
from security.password_policy import get_password_strength, get_policy_requirements


@bp.route('/api/v2/users/password-policy', methods=['GET'])
def get_password_policy():
    """
    Get password policy requirements

    GET /api/v2/users/password-policy

    Returns password requirements for UI display
    """
    return success_response(data=get_policy_requirements())


@bp.route('/api/v2/users/password-strength', methods=['POST'])
def check_password_strength():
    """
    Check password strength (no auth required - used during registration/password change)

    POST /api/v2/users/password-strength
    {"password": "test123"}

    Returns strength score and feedback
    """
    data = request.get_json() or {}
    password = data.get('password', '')

    return success_response(data=get_password_strength(password))
