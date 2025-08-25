from blueprints.auth.auth_config import AuthConfig
from flask import Blueprint, request, jsonify, current_app
from functools import wraps
import jwt
import os
import sys

auth_bp = Blueprint('auth', __name__)


def verify_jwt_token(token):
    """
    Verify a JWT token and return the decoded payload.

    Args:
        token (str): The JWT token to verify

    Returns:
        dict: Decoded token payload if valid, None if invalid
    """
    try:
        # Get the JWT secret key from config - use JWT_SECRET to match ai-login-microservice
        secret_key = AuthConfig.JWT_SECRET
        print(f"🔧 JWT VERIFICATION DEBUG:", file=sys.stderr)
        print(f"   Using JWT secret: {repr(secret_key)}", file=sys.stderr)
        print(
            f"   Token to verify: {token[:50] if token else 'None'}...{token[-20:] if token and len(token) > 70 else ''}", file=sys.stderr)
        print(
            f"   Token length: {len(token) if token else 0}", file=sys.stderr)

        # Decode and verify the token
        payload = jwt.decode(
            token,
            secret_key,
            algorithms=['HS256']
        )
        print(f"   ✅ JWT verification successful: {payload}", file=sys.stderr)
        return payload
    except jwt.ExpiredSignatureError as e:
        print(f"   ⏰ JWT token expired: {e}", file=sys.stderr)
        return None
    except jwt.InvalidSignatureError as e:
        print(f"   🔑 JWT invalid signature: {e}", file=sys.stderr)
        print(f"   This usually means wrong JWT_SECRET", file=sys.stderr)
        return None
    except jwt.InvalidTokenError as e:
        print(f"   ❌ JWT token invalid: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(
            f"   💥 Unexpected JWT error: {type(e).__name__}: {e}", file=sys.stderr)
        return None


def jwt_required(f):
    """
    Decorator to require JWT authentication for a route.

    Usage:
        @auth_bp.route('/protected')
        @jwt_required
        def protected_route():
            return jsonify({'message': 'Access granted'})
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None

        # Check for token in Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                # Extract token from "Bearer <token>" format
                token = auth_header.split(' ')[1]
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401

        # Check for token in cookies
        elif 'jwt_token' in request.cookies:
            token = request.cookies.get('jwt_token')

        # Check for token in request body (for JSON requests)
        elif request.is_json and 'token' in request.get_json():
            token = request.get_json()['token']

        # Check for token in form data (for POST from ai-login-microservice)
        elif request.method == 'POST' and 'token' in request.form:
            token = request.form['token']

        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        # Verify the token
        payload = verify_jwt_token(token)
        if payload is None:
            return jsonify({'error': 'Token is invalid or expired'}), 401

        # Add user info to request context
        request.current_user = payload

        return f(*args, **kwargs)

    return decorated_function


@auth_bp.route('/verify', methods=['POST'])
def verify_token():
    """
    Endpoint to verify if a JWT token is valid.

    Expects JSON: {"token": "your_jwt_token"}
    Returns: {"valid": true/false, "user": user_data}
    """
    data = request.get_json()

    if not data or 'token' not in data:
        return jsonify({'error': 'Token is required'}), 400

    token = data['token']
    payload = verify_jwt_token(token)

    if payload:
        return jsonify({
            'valid': True,
            'user': payload
        }), 200
    else:
        return jsonify({
            'valid': False,
            'error': 'Invalid or expired token'
        }), 401


@auth_bp.route('/check', methods=['GET'])
@jwt_required
def check_auth():
    """
    Protected endpoint to check if user is authenticated.
    Requires JWT token in Authorization header, cookies, or request body.
    """
    return jsonify({
        'authenticated': True,
        'user': request.current_user
    }), 200


@auth_bp.route('/user', methods=['GET'])
@jwt_required
def get_user_info():
    """
    Get current user information from JWT token.
    """
    return jsonify({
        'user': request.current_user
    }), 200
