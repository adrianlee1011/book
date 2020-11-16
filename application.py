import os

from flask import Flask, session, render_template, request, url_for, redirect, flash, jsonify, abort
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from flask_bcrypt import Bcrypt
from functools import wraps
import requests

app = Flask(__name__)
bcrypt = Bcrypt(app)
# Check for environment variable
if not os.getenv("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL is not set")

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Set up database
engine = create_engine(os.getenv("DATABASE_URL"))
db = scoped_session(sessionmaker(bind=engine))


# decorator for login required
def login_required(f):
    @wraps(f) # imported from functools, wraps around the whole function
    def wrap(*args, **kwargs):
        if 'user_id' in session:
            return f(*args, **kwargs)
        else:
            flash("You need to log in to view this page.")
            return redirect(url_for('login'))

    return wrap


@app.route("/", methods=["GET", "POST"])
def index():
    if 'user_id' in session:
        user = db.execute("SELECT * FROM users WHERE id = :id", {"id": session['user_id']}).fetchone()
        username = user.username
    else:
        username = "Guest"

    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")
        password.replace("'", "\'")
        user = db.execute("SELECT * FROM users WHERE username = :username", {"username": username.strip()}).fetchone()
        if user is None:
            flash('No such user exists. Please register.')
            return redirect(url_for('login'))
        if not bcrypt.check_password_hash(user['password_hash'].strip(), password):
            flash('Invalid password.')
            return redirect(url_for('login'))
        session['user_id'] = user['id']
        session['username'] = user['username']
    return render_template("index.html", username=username)


@app.route("/login")
def login():
    return render_template("login.html", title="Log In")


@app.route("/logout")
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You are logged out.')
    return redirect(url_for('index'))


@app.route("/register")
def register():
    return render_template("register.html", title="Register")


@app.route("/success", methods=["POST"])
def success():
    username = request.form.get("username")
    email = request.form.get("email")
    password1 = request.form.get("password")
    password2 = request.form.get("password2")

    if db.execute("SELECT * FROM users WHERE username = :username", {"username": username}).rowcount != 0:
        flash('Username is already taken.')
        return redirect(url_for('register'))

    if db.execute("SELECT * FROM users WHERE email = :email", {"email": email}).rowcount != 0:
        flash("Email is already taken.")
        return redirect(url_for('register'))

    if password1 != password2:
        flash("Passwords do not match.")
        return redirect(url_for('register'))

    pw_hash = bcrypt.generate_password_hash(password1).decode('utf-8')
    
    db.execute("INSERT INTO users (username, email, password_hash) VALUES (:username, :email, :password_hash)", {"username": username, "email": email, "password_hash": pw_hash})
    db.commit()

    return render_template("success.html", title="Register Successful")


@app.route("/search")
@login_required
def search():
    return render_template("search.html", title="Search Books")


@app.route("/results", methods=['POST'])
@login_required
def results():
    keyword = str(request.form.get("search-keyword"))
    show_keyword = keyword
    keyword = keyword.replace("'", "\'\'")
    keyword = '%' + keyword + '%'
    search_by_choice = request.form.get("search-by")
    search_result = db.execute(f"SELECT * FROM books WHERE LOWER({search_by_choice}) LIKE LOWER(\'{keyword}\')").fetchall()
    if len(search_result) == 0:
        flash("No results found.")
        return redirect(url_for('search'))

    return render_template("results.html", title="Search Results", books=search_result, keyword=show_keyword, choice=search_by_choice)


@app.route("/book/<string:isbn>", methods=['GET', 'POST'])
@login_required
def get_book_details(isbn):
    isbn = isbn.replace("'", "\'")
    book = db.execute("SELECT * FROM books WHERE LOWER(isbn) = LOWER(:isbn)", {"isbn": isbn}).fetchone()
    if book is None:
        flash("No book found.")
        return redirect(url_for('index'))

    res = requests.get("https://www.goodreads.com/book/review_counts.json", params={"key": "xVfqCreIiXViAZUKokbg", "isbns": isbn})
    if not res.ok:
        res = None
    res = res.json()

    reviews = db.execute("SELECT reviews.rating, reviews.review, users.username FROM reviews JOIN users ON reviews.book = :isbn AND users.id = reviews.user_id", {"isbn": book.isbn}).fetchall()

    if request.method == "POST":
        review = request.form.get("review-text")
        review = review.replace("'", "''")
        rating = int(request.form.get("rating"))
        for rev in reviews:
            if session['username'] == rev[2]:
                flash("You can only submit a review of a book once.")
                return redirect(url_for('get_book_details', isbn=isbn))
        db.execute("INSERT INTO reviews (book, rating, review, user_id) VALUES (:book, :rating, :review, :user_id)", {"book": isbn, "rating": rating, "review": review, "user_id": session['user_id']})
        db.commit()
        flash("Review submitted")
        return redirect(url_for('get_book_details', isbn=isbn))

    return render_template("book.html", title=book.title, book=book, goodreads=res, reviews=reviews)


@app.route("/api/<string:isbn>")
def get_api(isbn):
    isbn = isbn.replace("'", "\'")
    book = db.execute("SELECT * FROM books WHERE LOWER(isbn) = LOWER(:isbn)", {"isbn": isbn}).fetchone()
    if book is None:
        return abort(404, description="Book not found")

    res = requests.get("https://www.goodreads.com/book/review_counts.json", params={"key": "xVfqCreIiXViAZUKokbg", "isbns": isbn})
    if not res.ok:
        res = None
    res = res.json()
    return jsonify(
        title=book.title,
        author=book.author,
        year=book.year,
        isbn=book.isbn,
        review_count=res['books'][0]['work_ratings_count'],
        average_score=res['books'][0]['average_rating']
    )


@app.route("/user/<username>")
@login_required
def user(username):
    user = db.execute("SELECT * FROM users WHERE username = :username", {"username": username}).fetchone()
    reviews = db.execute("SELECT * FROM reviews WHERE user_id = :user_id", {"user_id": user.id}).fetchall()
    return render_template("user.html", user=user, reviews=reviews)
