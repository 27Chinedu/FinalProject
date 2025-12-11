from app.database import engine
from app.models.user import Base

def init_db():
    Base.metadata.create_all(bind=engine)

def drop_db():
    """Drop all database tables using CASCADE to handle foreign keys."""
    from sqlalchemy import text
    # Drop tables with CASCADE to handle foreign key constraints
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS calculations CASCADE"))
        conn.execute(text("DROP TABLE IF EXISTS users CASCADE"))

if __name__ == "__main__":
    init_db()