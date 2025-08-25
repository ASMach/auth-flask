from config import Config


class AuthConfig:
    # Import auth-related settings from the main Config class
    LOGIN_MICROSERVICE_URL = getattr(Config, 'LOGIN_MICROSERVICE_URL', 'http://localhost:8080')
    JWT_SECRET = getattr(Config, 'JWT_SECRET', 'jwt-secret')
