# JWT Authentication Blueprint

This blueprint provides JWT (JSON Web Token) authentication functionality for the Style Transfer Tool.

## Features

- JWT token validation
- Multiple token input methods (Authorization header, cookies, request body)
- Protected route decorator
- Token verification endpoints

## Endpoints

### POST `/auth/verify`
Verify if a JWT token is valid.

**Request Body:**
```json
{
  "token": "your_jwt_token_here"
}
```

**Response (Valid Token):**
```json
{
  "valid": true,
  "user": {
    "user_id": 123,
    "username": "testuser",
    "email": "test@example.com"
  }
}
```

**Response (Invalid Token):**
```json
{
  "valid": false,
  "error": "Invalid or expired token"
}
```

### GET `/auth/check`
Protected endpoint to check if user is authenticated.

**Headers:**
```
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "authenticated": true,
  "user": {
    "user_id": 123,
    "username": "testuser",
    "email": "test@example.com"
  }
}
```

### GET `/auth/user`
Get current user information from JWT token.

**Headers:**
```
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "user": {
    "user_id": 123,
    "username": "testuser",
    "email": "test@example.com"
  }
}
```

## Usage

### Protecting Routes

Use the `@jwt_required` decorator to protect any route:

```python
from blueprints.auth import jwt_required

@app.route('/protected')
@jwt_required
def protected_route():
    # Access user info from the JWT token
    user_info = request.current_user
    return jsonify({'message': f'Hello {user_info["username"]}!'})
```

### Token Input Methods

The blueprint accepts JWT tokens in three ways:

1. **Authorization Header (Recommended):**
   ```
   Authorization: Bearer <your_jwt_token>
   ```

2. **Cookies:**
   ```
   Cookie: jwt_token=<your_jwt_token>
   ```

3. **Request Body (POST requests only):**
   ```json
   {
     "token": "<your_jwt_token>"
   }
   ```

## Configuration

### Environment Variables

- `JWT_SECRET`: Secret key for JWT signing (must match the ai-login-microservice JWT_SECRET)

### Token Requirements

- Algorithm: HS256
- Required fields: None (flexible payload structure)
- Expiration: Tokens should include an `exp` claim

## Testing

Run the test script to verify functionality:

```bash
# Start the Flask app
python app.py

# In another terminal, run the test
python test_jwt.py
```

## Security Notes

- Always use HTTPS in production
- Use strong, random secret keys
- Implement proper token expiration
- Consider implementing token refresh logic
- Validate user permissions within your application logic