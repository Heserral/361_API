import aiomysql
from core.config import mysql_host, mysql_user, mysql_password, mysql_database
from core.logger import logger

class MySQLManager:
    _pool: aiomysql.Pool = None

    @classmethod
    async def connect(cls):
        """Establece la conexión con MySQL si aún no está conectada."""
        if cls._pool is None:
            try:
                cls._pool = await aiomysql.create_pool(
                    host=mysql_host,
                    port=3306,
                    user=mysql_user,
                    password=mysql_password,
                    db=mysql_database,
                    maxsize=100,
                    minsize=10,
                    connect_timeout=5,
                    charset="utf8mb4",
                    autocommit=True
                )
                # Verifica la conexión
                async with cls._pool.acquire() as conn:
                    async with conn.cursor() as cursor:
                        await cursor.execute("SELECT 1")
                        await conn.commit()
                logger.info("Conexión a MySQL establecida correctamente.")
            except Exception as e:
                logger.error(f"Error al conectar con MySQL: {e}")
                cls._pool = None
                raise

    @classmethod
    async def close(cls):
        """Cierra la conexión con MySQL."""
        if cls._pool:
            cls._pool.close()
            await cls._pool.wait_closed()
            logger.info("Conexión a MySQL cerrada.")
            cls._pool = None

    @classmethod
    async def get_pool(cls):
        """Obtiene el pool de conexiones a MySQL."""
        if cls._pool is None:
            await cls.connect()
        return cls._pool

    @classmethod
    async def get_connection(cls):
        """Obtiene una conexión del pool."""
        pool = await cls.get_pool()
        return await pool.acquire()