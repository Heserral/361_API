import asyncio
import json
from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from keycloak import KeycloakOpenID
from core.config import keycloak_server_url, keycloak_realm, keycloak_client_id, keycloak_client_secret, keycloak_verify
from core.logger import logger
from core.db import MySQLManager


# AuthMiddleware --> dispatch --> get_current_user (Auth o x-api) --> introspect_keycloak_token(comprueba token y retorna info del usuario desd BD) --> dispatch -> request.state.user --> call_next

# Configuración de Keycloak
keycloak_openid = KeycloakOpenID(
    server_url=keycloak_server_url,
    realm_name=keycloak_realm,
    client_id=keycloak_client_id,
    client_secret_key=keycloak_client_secret,
    verify=keycloak_verify  # True en producción
)

# Lista de rutas excluidas de autenticación para poder utilizar el token de autenticación en /docs
EXCLUDED_PATHS = {"/docs", "/openapi.json", "/redoc", "/api/token", "/docs/oauth2-redirect"}

async def introspect_keycloak_token(token: str, is_client_credentials: bool = False):
    try:
        token_info = keycloak_openid.introspect(token)
        if not token_info.get("active", False):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Token caducado"}
            )

        #----------------COMPROBAMOS SI ES UN TOKEN DE CLIENTE--------------------------------
        if is_client_credentials:
            # Validar token de client credentials
            if "client_id" not in token_info:
                logger.error("Token no contiene client_id")
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Token no válido para client credentials"}
                )

            # Opcional: Verificar roles o scopes del cliente
            required_roles = ["your_required_client_role"]  # Configura los roles necesarios
            client_roles = token_info.get("resource_access", {}).get(keycloak_client_id, {}).get("roles", [])
            if not any(role in client_roles for role in required_roles):
                logger.error(f"El cliente no tiene los roles requeridos: {required_roles}")
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Cliente no autorizado: roles insuficientes"}
                )

            # Opcional: Verificar scopes
            required_scopes = ["your_required_scope"]  # Configura los scopes necesarios
            token_scopes = token_info.get("scope", "").split()
            if not all(scope in token_scopes for scope in required_scopes):
                logger.error(f"El cliente no tiene los scopes requeridos: {required_scopes}")
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Cliente no autorizado: scopes insuficientes"}
                )

            # Retornar información del cliente
            return {
                "client_id": token_info.get("client_id"),
                "roles": client_roles,
                "scopes": token_scopes,
                "type": "client"
            }

        #----------------COMPROBAMOS SI ES UN TOKEN DE USUARIO--------------------------------
        else:
            # Lógica existente para autenticación de usuarios
            if "email" not in token_info:
                logger.error("Token no contiene email")
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Token no válido para usuario"}
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

            return {
                "email": token_info["email"],
                "sub": token_info["sub"],
                "roles": token_info.get("resource_access", {}).get(keycloak_client_id, {}).get("roles", []),
                "type": "user"
            }

    except Exception as exc:
        logger.error(f"Error al introspectar token: {exc}")
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Error de autenticación"}
        )

async def get_current_user(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "No se proporcionaron credenciales de autenticación"}
        )

    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Formato de token inválido"}
        )

    # Intentar como token de usuario primero
    user_info = await introspect_keycloak_token(token, is_client_credentials=False)
    if isinstance(user_info, JSONResponse) and "no válido para usuario" in user_info.body.decode():
        # Si falla como usuario, intentar como client credentials
        user_info = await introspect_keycloak_token(token, is_client_credentials=True)

    if isinstance(user_info, JSONResponse):
        return user_info

    if not user_info:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Token inactivo o expirado"}
        )


    # #----------------API KEY--------------------------------
    # elif request.headers.get("X-API-Key"):
    #     user_info = arequest.headers.get("X-API-Key")
        # db = await MySQLManager.get_connection()
        # async with db.cursor() as cursor:
        #     await cursor.execute("SELECT * FROM users WHERE apikey = %s", (user_info,))
        #     user_info = await cursor.fetchone()
        # if user_info is None:
        #     logger.error(f"El usuario {user_info} no existe en la base de datos")
        #     return JSONResponse(
        #         status_code=status.HTTP_401_UNAUTHORIZED,
        #         content={"detail": "Error de autenticación"}
        #     )
    #     if isinstance(user_info, JSONResponse):
    #         return user_info
    #     if not user_info:
    #         return JSONResponse(
    #             status_code=status.HTTP_401_UNAUTHORIZED,
    #             content={"detail": "API key revocada o inválida"}
    #         )
    #     return user_info

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