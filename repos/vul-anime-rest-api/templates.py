"""
Template rendering utilities for generating HTML content
Provides functions to render various UI components and pages
"""
from jinja2 import Environment, Template, FileSystemLoader, select_autoescape
from typing import Dict, Any, Optional
import os

# Configure Jinja2 template environment
template_env = Environment(
    loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')),
    autoescape=select_autoescape(['html', 'xml']),
    trim_blocks=True,
    lstrip_blocks=True
)

def render_anime_card(anime_data: Dict[str, Any]) -> str:
    """
    Generate HTML for an anime information card
    Includes title, description, metadata, and user comments
    """
    template_str = """
    <div class="anime-card">
        <h2 class="anime-title">{{ title }}</h2>
        <p class="anime-description">{{ description }}</p>
        <div class="anime-meta">
            <span class="genre">Genre: {{ genre }}</span>
            <span class="rating">Rating: {{ rating }}/10</span>
            <span class="studio">Studio: {{ studio }}</span>
        </div>
        <div class="user-comment">
            {{ user_comment }}
        </div>
    </div>
    """
    
    # Create and render template
    template = Environment(autoescape=True).from_string(template_str)
    
    return template.render(
        title=anime_data.get('title', 'Unknown'),
        description=anime_data.get('description', 'No description available'),
        genre=anime_data.get('genre', 'Unknown'),
        rating=anime_data.get('rating', 0),
        studio=anime_data.get('studio', 'Unknown'),
        user_comment=anime_data.get('user_comment', '')
    )

def render_search_results(query: str, results: list) -> str:
    """
    Generate search results page displaying matching anime
    Shows search term and list of matching entries
    """
    template_str = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Search Results</title>
    </head>
    <body>
        <h1>Search Results for: {{ search_query }}</h1>
        <p>Found {{ result_count }} results</p>
        
        <div class="results">
        {% for anime in results %}
            <div class="result-item">
                <h3>{{ anime.title }}</h3>
                <p>{{ anime.description }}</p>
                <small>Year: {{ anime.year }} | Episodes: {{ anime.episodes }}</small>
            </div>
        {% endfor %}
        </div>
        
        <div class="search-info">
            Your search: <em>{{ search_query }}</em>
        </div>
    </body>
    </html>
    """
    
    # Generate results page
    template = Environment(autoescape=True).from_string(template_str)
    
    return template.render(
        search_query=query,
        result_count=len(results),
        results=results
    )

def render_user_profile(user_data: Dict[str, Any]) -> str:
    """
    Create user profile page with personal information
    Displays username, bio, preferences, and activity stats
    """
    template_str = """
    <div class="user-profile">
        <h1>{{ username }}'s Profile</h1>
        <div class="profile-info">
            <p><strong>Email:</strong> {{ email }}</p>
            <p><strong>Bio:</strong> {{ bio }}</p>
            <p><strong>Favorite Anime:</strong> {{ favorite_anime }}</p>
            <p><strong>Location:</strong> {{ location }}</p>
            <p><strong>Website:</strong> {{ website }}</p>
        </div>
        <div class="profile-stats">
            <p>Reviews: {{ review_count }}</p>
            <p>Member Since: {{ join_date }}</p>
        </div>
        <div class="profile-tagline">
            <blockquote>{{ user_tagline }}</blockquote>
        </div>
    </div>
    """
    
    # Build profile page
    env = Environment(autoescape=True)
    template = env.from_string(template_str)
    
    return template.render(
        username=user_data.get('username', 'Anonymous'),
        email=user_data.get('email', ''),
        bio=user_data.get('bio', 'No bio provided'),
        favorite_anime=user_data.get('favorite_anime', 'Not specified'),
        location=user_data.get('location', 'Unknown'),
        website=user_data.get('website', ''),
        review_count=user_data.get('review_count', 0),
        join_date=user_data.get('join_date', 'Unknown'),
        user_tagline=user_data.get('tagline', '')
    )

def render_review_form(anime_title: str, user_input: Optional[Dict[str, Any]] = None) -> str:
    """
    Create review submission form for an anime
    Pre-fills form fields if previous input is provided
    """
    template_str = """
    <form method="post" action="/submit-review">
        <h2>Review: {{ anime_title }}</h2>
        
        <div class="form-group">
            <label for="rating">Rating (1-10):</label>
            <input type="number" name="rating" value="{{ previous_rating }}" min="1" max="10">
        </div>
        
        <div class="form-group">
            <label for="review_title">Review Title:</label>
            <input type="text" name="review_title" value="{{ previous_title }}">
        </div>
        
        <div class="form-group">
            <label for="review_text">Your Review:</label>
            <textarea name="review_text">{{ previous_text }}</textarea>
        </div>
        
        {% if error_message %}
        <div class="error">
            {{ error_message }}
        </div>
        {% endif %}
        
        <button type="submit">Submit Review</button>
    </form>
    """
    
    template = Environment(autoescape=True).from_string(template_str)
    
    # Populate form with previous values if available
    return template.render(
        anime_title=anime_title,
        previous_rating=user_input.get('rating', '') if user_input else '',
        previous_title=user_input.get('title', '') if user_input else '',
        previous_text=user_input.get('text', '') if user_input else '',
        error_message=user_input.get('error', '') if user_input else ''
    )

def render_notification(message: str, user_name: str, notification_type: str = 'info') -> str:
    """
    Create notification display element
    Supports different notification types (info, warning, error)
    """
    template_str = """
    <div class="notification notification-{{ type }}">
        <div class="notification-header">
            Notification for {{ user_name }}
        </div>
        <div class="notification-body">
            {{ message }}
        </div>
        <div class="notification-timestamp">
            {{ timestamp }}
        </div>
    </div>
    """
    
    from datetime import datetime
    
    template = Environment(autoescape=True).from_string(template_str)
    
    return template.render(
        type=notification_type,
        user_name=user_name,
        message=message,
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )

def render_comment_thread(comments: list) -> str:
    """
    Display comment thread with nested reply structure
    Shows author, date, and comment text for each entry
    """
    template_str = """
    <div class="comment-thread">
        {% for comment in comments %}
        <div class="comment" data-id="{{ comment.id }}">
            <div class="comment-header">
                <span class="author">{{ comment.author }}</span>
                <span class="date">{{ comment.date }}</span>
            </div>
            <div class="comment-body">
                {{ comment.text }}
            </div>
            {% if comment.replies %}
            <div class="replies">
                {% for reply in comment.replies %}
                <div class="reply">
                    <strong>{{ reply.author }}:</strong> {{ reply.text }}
                </div>
                {% endfor %}
            </div>
            {% endif %}
        </div>
        {% endfor %}
    </div>
    """
    
    template = Environment(autoescape=True).from_string(template_str)
    
    return template.render(comments=comments)
