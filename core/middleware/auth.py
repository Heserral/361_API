import asyncio
import json
from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from keycloak import KeycloakOpenID
from core.config import keycloak_server_url, keycloak_realm, keycloak_client_id, keycloak_client_secret, keycloak_verify
from core.logger import logger
from core.db import MySQLManager

# Configuración de Keycloak
keycloak_openid = KeycloakOpenID(
    server_url=keycloak_server_url,
    realm_name=keycloak_realm,
    client_id=keycloak_client_id,
    client_secret_key=keycloak_client_secret,
    verify=keycloak_verify  # True en producción
)

# Lista de rutas excluidas de autenticación
EXCLUDED_PATHS = {"/docs", "/openapi.json", "/redoc", "/api/token", "/docs/oauth2-redirect"}

async def introspect_keycloak_token(token: str):
    try:
        # Se realiza la introspección en un hilo separado para no bloquear el event loop
        token_info = keycloak_openid.introspect(token)
        if not token_info.get("active", False):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Token caducado"}
            )

        # db = await MySQLManager.get_connection()
        # async with db.cursor() as cursor:
        #     await cursor.execute("SELECT * FROM users WHERE email = %s", (token_info["email"],))
        #     user_info = await cursor.fetchone()
        # if user_info is None:
        #     logger.error(f"El usuario {token_info['email']} no existe en la base de datos")
        #     return JSONResponse(
        #         status_code=status.HTTP_401_UNAUTHORIZED,
        #         content={"detail": "Error de autenticación"}
        #     )

        return token_info
    except Exception as exc:
        logger.error(f"Error al introspectar token: {exc}")
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Error de autenticación"}
        )

async def get_current_user(request: Request):
    #----------------BEARER HEADER--------------------------------
    auth_header = request.headers.get("Authorization")
    if auth_header:
        scheme, _, token = auth_header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Formato de token inválido"}
            )
        user_info = await introspect_keycloak_token(token)
        # Si se retorna un JSONResponse, es que hubo un error
        if isinstance(user_info, JSONResponse):
            return user_info
        if not user_info:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Token inactivo o expirado"}
            )
        return user_info

    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": "No se proporcionaron credenciales de autenticación"}
    )

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Bypass authentication for excluded paths
        if request.url.path in EXCLUDED_PATHS:
            return await call_next(request)

        user_info = await get_current_user(request)
        # Si se obtuvo un JSONResponse, significa que ocurrió un error de autenticación
        if isinstance(user_info, JSONResponse):
            # Para efectos de log, decodificamos el body (que es bytes)
            try:
                error_detail = json.loads(user_info.body.decode())
            except Exception:
                error_detail = user_info.body.decode()
            logger.warning(f"Autenticación fallida: {error_detail}")
            return user_info

        request.state.user = user_info
        response = await call_next(request)
        return response