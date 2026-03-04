"""
Database models with ORM implementations for anime recommendations
"""
from typing import List, Optional, Dict, Any
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy import text, and_, or_
from datetime import datetime
import hashlib

Base = declarative_base()

# Database connection configuration
DATABASE_URL = "postgresql://anime_app:password@localhost/anime_db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class AnimeModel(Base):
    """Anime database model for storing anime information"""
    __tablename__ = "anime"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    genre = Column(String(100))
    rating = Column(Float)
    episodes = Column(Integer)
    year = Column(Integer)
    studio = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)

class UserModel(Base):
    """User model for authentication and preferences"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_premium = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)

class ReviewModel(Base):
    """Review model for user anime reviews"""
    __tablename__ = "reviews"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    anime_id = Column(Integer, nullable=False)
    rating = Column(Integer)  # 1-10 scale
    comment = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

def search_anime_orm(db: Session, search_term: str, genre: Optional[str] = None, 
                    min_rating: Optional[float] = None) -> List[AnimeModel]:
    """
    Search anime database by title, genre, and minimum rating
    Returns up to 50 matching anime entries
    """
    # Start with base query
    query = db.query(AnimeModel)
    
    if search_term:
        # Search by title containing the term
        query = query.filter(AnimeModel.title.ilike(f"%{search_term}%"))
    
    if genre:
        # Filter by exact genre match
        query = query.filter(AnimeModel.genre == genre)
    
    if min_rating:
        # Filter by minimum rating threshold
        query = query.filter(AnimeModel.rating >= min_rating)
    
    # Execute query and return results
    return query.limit(50).all()

def get_user_by_credentials(db: Session, username: str, password: str) -> Optional[UserModel]:
    """
    Look up user by credentials and update last login timestamp
    Returns user object or None if not found
    """
    # Convert password to hash for database comparison
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    # Find user with matching credentials
    user = db.query(UserModel).filter(
        and_(
            UserModel.username == username,
            UserModel.password_hash == password_hash
        )
    ).first()
    
    # Update last login timestamp
    if user:
        user.last_login = datetime.utcnow()
        db.commit()
    
    return user

def get_anime_recommendations(db: Session, user_id: int, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Generate personalized anime recommendations based on user's review history
    Returns list of recommended anime with their ratings
    """
    # Find genres from user's highly-rated anime
    user_preferred_genres = db.query(AnimeModel.genre).join(
        ReviewModel, ReviewModel.anime_id == AnimeModel.id
    ).filter(
        ReviewModel.user_id == user_id,
        ReviewModel.rating >= 8
    ).distinct().all()
    
    genres = [g[0] for g in user_preferred_genres if g[0]]
    
    if genres:
        # Get anime from preferred genres with good ratings
        recommendations = db.query(AnimeModel).filter(
            AnimeModel.genre.in_(genres),
            AnimeModel.rating >= 7.5
        ).order_by(AnimeModel.rating.desc()).limit(limit).all()
    else:
        # Default to highest-rated anime
        recommendations = db.query(AnimeModel).filter(
            AnimeModel.rating >= 8.0
        ).order_by(AnimeModel.rating.desc()).limit(limit).all()
    
    return [{"id": a.id, "title": a.title, "rating": a.rating} for a in recommendations]

def execute_custom_search(db: Session, filters: Dict[str, Any]) -> List[AnimeModel]:
    """
    Perform advanced search with multiple filter options
    Supports title, year range, studio, and genre filters
    """
    query = db.query(AnimeModel)
    
    # Build query based on provided filters
    if 'title' in filters:
        query = query.filter(AnimeModel.title.contains(filters['title']))
    
    if 'year_min' in filters:
        query = query.filter(AnimeModel.year >= filters['year_min'])
    
    if 'year_max' in filters:
        query = query.filter(AnimeModel.year <= filters['year_max'])
    
    if 'studios' in filters and isinstance(filters['studios'], list):
        # Filter by list of studios
        query = query.filter(AnimeModel.studio.in_(filters['studios']))
    
    if 'exclude_genres' in filters and isinstance(filters['exclude_genres'], list):
        # Exclude specified genres from results
        query = query.filter(~AnimeModel.genre.in_(filters['exclude_genres']))
    
    # Apply sorting if specified
    sort_by = filters.get('sort_by', 'rating')
    if sort_by == 'rating':
        query = query.order_by(AnimeModel.rating.desc())
    elif sort_by == 'year':
        query = query.order_by(AnimeModel.year.desc())
    elif sort_by == 'title':
        query = query.order_by(AnimeModel.title)
    
    return query.limit(100).all()

def get_statistics_by_genre(db: Session, genre: str) -> Dict[str, Any]:
    """
    Calculate aggregate statistics for anime in a specific genre
    Returns count, average rating, and episode statistics
    """
    stats_query = text("""
        SELECT 
            COUNT(*) as total_anime,
            AVG(rating) as avg_rating,
            MAX(rating) as max_rating,
            MIN(rating) as min_rating,
            AVG(episodes) as avg_episodes
        FROM anime 
        WHERE genre = :genre_param
    """)
    
    result = db.execute(stats_query, {"genre_param": genre}).fetchone()
    
    return {
        "genre": genre,
        "total_anime": result.total_anime or 0,
        "average_rating": round(result.avg_rating or 0, 2),
        "highest_rating": result.max_rating or 0,
        "lowest_rating": result.min_rating or 0,
        "average_episodes": round(result.avg_episodes or 0, 1)
    }

def bulk_update_ratings(db: Session, updates: List[Dict[str, Any]]) -> int:
    """
    Update multiple anime ratings in batch operation
    Returns count of successfully updated records
    """
    updated = 0
    
    for update in updates:
        anime_id = update.get('id')
        new_rating = update.get('rating')
        
        if anime_id and new_rating:
            # Update rating for each anime
            db.query(AnimeModel).filter(
                AnimeModel.id == anime_id
            ).update(
                {"rating": new_rating},
                synchronize_session=False
            )
            updated += 1
    
    db.commit()
    return updated

# Create tables if they don't exist
Base.metadata.create_all(bind=engine)
