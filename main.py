from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from core.logger import logger
from core.db import MySQLManager

from fastapi.security import OAuth2AuthorizationCodeBearer
from core.middleware.auth import AuthMiddleware
from core.config import keycloak_server_url, keycloak_realm, keycloak_client_id, keycloak_client_secret

# from core.middleware.ratelimit import RateLimitMiddleware
# from core.middleware.routeauth import RouteAuthMiddleware
from routes import router

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{keycloak_server_url}/realms/{keycloak_realm}/protocol/openid-connect/auth",
    tokenUrl=f"{keycloak_server_url}/realms/{keycloak_realm}/protocol/openid-connect/token",
    refreshUrl=f"{keycloak_server_url}/realms/{keycloak_realm}/protocol/openid-connect/token",
    scheme_name="Keycloak",
    scopes={
        "openid": "OpenID Connect scope",
        "profile": "Access to user profile",
        "email": "Access to user email"
    }
)

app = FastAPI(
    title="API BOEIA",
    version="1.0.0",
    redirect_slashes=False,
    description="""
        Documentación general de la API de BOEIA.
    """,
    dependencies=[Depends(oauth2_scheme)]
)



# Inicializamos el pool globalmente
#rabbitmq_pool: RabbitMQConnectionPool = None

@app.on_event("startup")
async def startup():
    await MySQLManager.connect()
    logger.info("Startup completo")

@app.on_event("shutdown")
async def shutdown():
    await MySQLManager.close()
    logger.info("shutdown event")

#-------------------------------------------------------------------------------------------------
# Recuerda que FastAPI (y Starlette) ejecuta los middlewares en orden inverso al que se agregan. 
# Request --> CORSMiddleware --> AuthMiddleware --> RouteAuthMiddleware --> RateLimitMiddleware --> Endpoints
#--------------------------------------------------------------------------------------------------
# app.add_middleware(RateLimitMiddleware)
# app.add_middleware(RouteAuthMiddleware)
app.add_middleware(AuthMiddleware)

app.add_middleware(
    # Si se desea más control, en settings.allowed_origins se puede definir una lista de orígenes permitidos
    # Ejemplo: ["https://tudominio.com", "https://otrodominio.com"]
    CORSMiddleware,
    allow_origins=["http://localhost:5174","*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router) #prefix='/api'
#app.include_router(router, dependencies=[Depends(get_current_user)])