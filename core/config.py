from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List

class Settings(BaseSettings):

    #-------------------------KEYCLOAK----------PORT=443------------------
    keycloak_server_url: str = Field("http://localhost", env="KEYCLOAK_SERVER_URL")
    keycloak_realm: str = Field("realm_name", env="KEYCLOAK_REALM")
    keycloak_client_id: str = Field("client_id", env="KEYCLOAK_CLIENT_ID")
    keycloak_client_secret: str = Field("client_secret", env="KEYCLOAK_CLIENT_SECRET")
    keycloak_verify: bool = Field(True, env="KEYCLOAK_VERIFY")
    #-------------------------MYSQL---------PORT=3306--------------
    mysql_host: str = Field("localhost", env="MYSQL_HOST")
    mysql_user: str = Field("username", env="MYSQL_USER")
    mysql_password: str = Field("password", env="MYSQL_PASSWORD")
    mysql_database: str = Field(..., env="MYSQL_DATABASE")
    #-------------------------REDIS--------PORT=6379-------------------
    redis_host: str = Field("localhost", env="REDIS_HOST")
    redis_username: str = Field("username", env="REDIS_USERNAME")
    redis_password: str = Field("password", env="REDIS_PASSWORD")
    redis_session_ttl: int = Field(300, env="REDIS_SESSION_TTL") #la cache de la sesion se corra cada 5 minutos

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

# Instantiate settings
_settings = Settings()

keycloak_server_url = _settings.keycloak_server_url
keycloak_realm = _settings.keycloak_realm
keycloak_client_id = _settings.keycloak_client_id
keycloak_client_secret = _settings.keycloak_client_secret
keycloak_verify = _settings.keycloak_verify

mysql_host = _settings.mysql_host
mysql_user = _settings.mysql_user
mysql_password = _settings.mysql_password
mysql_database = _settings.mysql_database

redis_host = _settings.redis_host
redis_username = _settings.redis_username
redis_password = _settings.redis_password
redis_session_ttl = _settings.redis_session_ttl


# Optionally, define __all__ to control what gets imported with "from module import *"
# __all__ = [
#     "mysql_uri",
#     "mysql_database",
#     "redis_host",
#     "redis_username",
#     "redis_password",
#     "redis_session_ttl",
#     "rabbitmq_username",
#     "rabbitmq_password",
#     "rabbitmq_host",
#     "rabbitmq_vhost",
#     "rabbitmq_ssl_enabled",
#     "rabbitmq_heartbeat",
#     "rabbitmq_cert_path",
#     "rabbitmq_ssl_key_path",
#     "rabbitmq_ssl_ca_path",
#     "rabbitmq_verify_ssl",
# ]