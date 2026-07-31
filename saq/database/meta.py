from sqlalchemy.orm import declarative_base

# main ace database
Base = declarative_base()

# analysis result cache database
CacheBase = declarative_base()

# brocess database
BrocessBase = declarative_base()
