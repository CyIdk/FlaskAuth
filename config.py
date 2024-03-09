from datetime import timedelta
class BasicConfig:
    # Perform the below in the terminal:
    # >>> import secrets
    # >>> secrets.token_hex()
    SECRET_KEY = "38829bbbcf8b4f960a0d6a0f05ef847c59bbca1162e8bf742f153ad226de1ca7"
    JWT_SECRET_KEY = "10f82c2c6b3033da41dd68f2380c01fc66bbd06f"
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)

class DevConfig(BasicConfig):
    DEBUG = True