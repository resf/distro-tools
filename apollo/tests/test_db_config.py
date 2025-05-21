import os
from tortoise import Tortoise

# Use SQLite for tests (in-memory or file-based)
TEST_DB_URL = "sqlite://:memory:"

# Define your models - make sure to include all models used in your application
TORTOISE_ORM = {
    "connections": {"default": TEST_DB_URL},
    "apps": {
        "models": {
            "models": [
                "apollo.db",  # Your main models
            ],
            "default_connection": "default",
        }
    },
}

async def initialize_test_db():
    """Initialize the test database with required schema"""
    await Tortoise.init(config=TORTOISE_ORM)
    await Tortoise.generate_schemas()

async def close_test_db():
    """Close database connections"""
    await Tortoise.close_connections()