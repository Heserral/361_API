from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from core.logger import logger
from core.db import MySQLManager
from urllib.parse import urlparse
from models.routes import Route
 
class RouteAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Verificar si request.state.user existe y contiene roles
        if not (hasattr(request.state, 'user') and ('roles' in request.state.user)):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": "No tienes permisos para acceder a esta ruta"}
            )
 
        user_info = request.state.user
 
        try:
            # Extraer la ruta sin querystring
            path = urlparse(str(request.url)).path
 
            db = await MySQLManager.get_connection()
            async with db.cursor(dictionary=True) as cursor: #Ensure cursor returns dictionaries
                await cursor.execute("SELECT * FROM routes WHERE path= %s AND roles=%s", (path,user_info['roles']))
                matching_route = await cursor.fetchone()
 
            if not matching_route:
                logger.warning(f"No route found for path: {path} with roles: {user_info['roles']}")
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Ruta no autorizada"}
                )

            try:
                route = Route(**matching_route)
                return await call_next(request)
            except ValueError as e:
                logger.error(f"Error casting route to model: {e}")
                return JSONResponse(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    content={"detail": "Error al procesar la ruta"}
                )

        except Exception as e:
            logger.error(f"Error al verificar la API key: {e}")
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": "Error al acceder a esta ruta"}
            )