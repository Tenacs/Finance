import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    id = session["user_id"]
    stocks = db.execute(
        "SELECT name, symbol, SUM(shares) AS shares, price, SUM(total) AS total FROM stocks WHERE user_id = ? GROUP BY symbol", id)
    userCash = db.execute("SELECT cash FROM users WHERE id = ?", id)
    cash = userCash[0]["cash"]
    total = db.execute("SELECT SUM(total) AS total FROM stocks WHERE user_id = ?", id)

    if total[0]["total"] == None:
        total = 0
    else:
        total = total[0]["total"]
    total += cash
    return render_template("index.html", stocks=stocks, cash=cash, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if shares.isdigit() and int(shares) >= 1:
            shares = int(shares)
        else:
            return apology("Enter valid number of shares", 400)

        # check if symbol is valid
        if not request.form.get("symbol") or not lookup(symbol):
            return apology("Invalid Symbol", 400)

        quote = lookup(symbol)
        total = round((shares * quote["price"]), 2)
        id = session["user_id"]
        userCash = db.execute("SELECT cash FROM users WHERE id = ?", id)
        userCash = userCash[0]["cash"]

        if userCash < total:
            return apology("Insufficient Balance", 400)

        # Creates purchases table
        db.execute("CREATE TABLE IF NOT EXISTS purchases (purchase_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, user_id INTEGER NOT NULL, name TEXT NOT NULL, symbol TEXT NOT NULL, shares INTEGER NOT NULL, price NUMERIC NOT NULL, total NUMERIC NOT NULL, date TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)")
        db.execute("INSERT INTO purchases (user_id, name, symbol, shares, price, total) VALUES (?, ?, ?, ?, ?, ?)",
                   id, quote["name"], quote["symbol"], shares, quote["price"], total)
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", total, id)

        # Creates current stocks table
        db.execute("CREATE TABLE IF NOT EXISTS stocks (user_id INTEGER NOT NULL, name TEXT NOT NULL, symbol TEXT NOT NULL, shares INTEGER NOT NULL DEFAULT 0, price NUMERIC NOT NULL DEFAULT 0, total NUMERIC NOT NULL DEFAULT 0)")
        db.execute("INSERT INTO stocks (user_id, name, symbol, shares, price, total) VALUES (?, ?, ?, ?, ?, ?)",
                   id, quote["name"], quote["symbol"], shares, quote["price"], total)

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    id = session["user_id"]

    transactions = db.execute(
        "SELECT symbol, shares, price, date FROM purchases WHERE user_id = ? UNION SELECT symbol, shares, price, date FROM sells WHERE user_id = ? ORDER BY date DESC", id, id)

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        symbol = request.form.get("symbol")
        quotes = lookup(symbol)
        if not quotes:
            return apology("Invalid symbol", 400)
        return render_template("quoted.html", quotes=quotes)

     # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not (request.form.get("password") or request.form.get("confirmation")):
            return apology("must provide password", 400)

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        usernames = db.execute("SELECT username FROM users WHERE username = ?", username)

        if len(usernames) != 0:
            return apology("Username not available", 400)
        if password != confirmation:
            return apology("Passwords do not match", 400)

        hash = generate_password_hash(password, method='pbkdf2', salt_length=16)

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)

        # Query database for id
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    id = session["user_id"]
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        # check if symbol is valid
        if not request.form.get("symbol") or not lookup(symbol):
            return apology("Invalid Symbol", 403)
        if shares < 1:
            return apology("Enter valid number of shares", 403)

        quote = lookup(symbol)
        totalSold = round((shares * quote["price"]), 2)

        totalStock = db.execute("SELECT SUM(total) AS total FROM stocks WHERE symbol = ?", symbol)

        if totalStock[0]["total"] == None:
            return apology("Invalid stock", 400)

        # Check if user doesn't have enough stock
        if totalStock[0]["total"] < totalSold:
            return apology("Too many shares", 400)

        # Creates sells table
        db.execute("CREATE TABLE IF NOT EXISTS sells (purchase_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, user_id INTEGER NOT NULL, name TEXT NOT NULL, symbol TEXT NOT NULL, shares INTEGER NOT NULL, price NUMERIC NOT NULL, total NUMERIC NOT NULL, date TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)")
        db.execute("INSERT INTO sells (user_id, name, symbol, shares, price, total) VALUES (?, ?, ?, ?, ?, ?)",
                   id, quote["name"], quote["symbol"], -shares, quote["price"], totalSold)

        #  updates users current stocks
        db.execute("UPDATE stocks SET shares = shares - ?, total = price * (shares - ?) WHERE user_id = ? AND symbol = ?",
                   shares, shares, id, symbol)

        # deletes stock if the value of shares is 0
        shareNum = db.execute("SELECT shares FROM stocks WHERE user_id = ? AND symbol = ?", id, symbol)
        if shareNum[0]["shares"] < 1:
            db.execute("DELETE FROM stocks WHERE user_id = ? AND symbol = ?", id, symbol)

        # updates user's cash
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", totalSold, id)

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        stocks = db.execute("SELECT DISTINCT symbol FROM stocks WHERE user_id = ?", id)
        return render_template("sell.html", stocks=stocks)
