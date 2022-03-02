import os
import re

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

# for password check
reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,18}$"
match_re = re.compile(reg)  # compiling regex

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")  # if method is not specified, by default it's "GET"
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]
    stocks = db.execute("SELECT symbol, name, SUM(shares) AS total_share FROM transactions WHERE user_id = ? GROUP BY symbol ORDER BY total_share DESC", user_id) 
    # price should extracted from lookup.
    real_price = {}  # declare real_price dictionary
    for i in range(len(stocks)):
        real_price[stocks[i]["symbol"]] = lookup(stocks[i]["symbol"])["price"]
    
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
    total = cash
    for stock in stocks:
        total += stock["total_share"] * real_price[stock["symbol"]]
    
    return render_template("index.html", stocks=stocks, cash=cash, usd=usd, total=total, real_price=real_price)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()  # symbol should be all uppercase
        if not symbol:
            return apology("Please type in the stock's symbol!")

        company = lookup(symbol)
        if not company: 
            return apology("Invalid symbol")

        try:
            shares = int(request.form.get("shares"))
        except:  # if error occurs (cannot convert the user input into int), return apology.
            return apology("Share must be an integer.")    

        if shares <= 0:
            return apology("Share must be a positive integer.")
            
        user_id = session["user_id"]

        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]  # the value of the first element where key is "cash". without [0]["cash"] the result would be [{"cash" : 10000}]


        total_price = company["price"] * shares

        if cash < total_price:
            return apology("Insufficient cash.")
        else:
            db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES (?, ?, ?, ?, ?, ?)", user_id, company["name"], shares, company["price"], "Buy", symbol) # INSERT new transaction activity
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - total_price, user_id) # UPDATE user profile

        return redirect("/")

    else:
        user_id = session["user_id"]
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        return render_template("/buy.html",cash=cash, usd=usd)


@app.route("/history", methods=["GET", "POST"])
@login_required
def history():
    """filter"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        type = request.form.get("type")
        if not symbol and not type:
            return apology("Filter not completed")

    else:
        # for filter options
        user_id = session["user_id"]
        symbols = db.execute("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)
        
        # Show history of transactions
        transactions = db.execute("SELECT symbol, type, shares, price, time FROM transactions WHERE user_id = ? ORDER BY time DESC", user_id) 

        return render_template("history.html", symbols=symbols, transactions=transactions, usd=usd)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST), which means the user has just submitted the login form 
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
    if request.method == "POST":
        symbol = request.form.get("symbol")

        # if there's no input
        if not symbol:
            return apology("Please type in the stock's symbol!")
        # pass the symbol into the predetermined lookup function 
        company = lookup(symbol)

        # if there's a mistake generating the item from lookup function
        if not company: 
            return apology("Invalid symbol")

        return render_template("/quoted.html", company=company, usd=usd)  # usd is a given function

    # if the form is not submitted via post, render to its owm template (quote.html)
    else:
        return render_template("/quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # declare variable and get the information from what the user register
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        
        # if any one is not typed in
        if not username:
            return apology("please type in username")
        elif not password:
            return apology("please type in password")
        elif not confirmation:
            return apology("please type in confirmation password") 

        # if the confirmation password and password do not match
        if password != confirmation:
            return apology("confirmation password and password do not match") 
        
        # check validity of te password: at least 4 chars, 1 alph, 1 num
        if not re.search(match_re, password):
            return apology("Invalid Password.")

        # create hash using the given function
        hash = generate_password_hash(password)
        # create new user
        try:
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash)
            return redirect("/")
        # if the user already exist
        except:
            return apology("username already exists")
        
    else:
        return render_template("/register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        user_id = session["user_id"]  # get session
        symbol = request.form.get("symbol").upper()  # get symbol
        shares_to_sell = int(request.form.get("shares"))  # get shares to sell
        shares_owned = db.execute("SELECT shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol", user_id, symbol)[0]["shares"]  # get the amount of shares the user owns

        # if the number is not valid
        if shares_to_sell <= 0:
            return apology("Shares has to be a positive integer!")
        elif shares_owned < shares_to_sell:
            return apology("Not enough shares!")

        company = lookup(symbol)  # get company's info. return "name", "price", "symbol"
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        total_price = company["price"] * shares_to_sell

        # update database
        db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES (?, ?, ?, ?, ?, ?)", user_id, company["name"], -shares_to_sell, company["price"], "Sell", symbol)  # INSERT new transaction activity
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash + total_price, user_id)  # UPDATE user profile

        return redirect("/")      

    else:
        user_id = session["user_id"]
        symbols = db.execute("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)
        return render_template("/sell.html", usd=usd, symbols=symbols)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        user_id = session["user_id"]
        username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]["username"]
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        form = request.form.get("form")
        
        # determine what form it is.
        if form == "reset_password_form":
            """Reset Password"""
            password = request.form.get("password")
            new_password = request.form.get("new_password")
            new_confirmation = request.form.get("new_confirmation")
            # if any one is not typed in
            if not password:
                return apology("please type in original password")
            elif not new_password:
                return apology("please type in new password")
            elif not new_confirmation:
                return apology("please confirm new password") 
            
            # check original password
            user_hash = db.execute("SELECT hash FROM users WHERE id = ?", user_id)[0]["hash"]
            if not check_password_hash(user_hash, password):
                return apology("Original password incorrect!")

            # if the confirmation password and password do not match
            if new_password != new_confirmation:
                return apology("new password and confirmation do not match")

            # check validity of te password: at least 4 chars, 1 alph, 1 num
            if not re.search(match_re, new_password): 
                return apology("Invalid Password.")

            new_hash = generate_password_hash(new_password)
            db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hash, user_id)
            cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"] # update cash

            return render_template("settings.html", username=username, cash=cash, usd=usd)

        elif form == "add_cash_form":
            """Add Cash"""
            add_cash = float(request.form.get("add_cash"))
            if not add_cash:
                return apology("please type in amount to add")
            elif add_cash <= 0:
                return apology("amount must be positive")

            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash + add_cash, user_id)

            return render_template("settings.html", username=username, cash=cash, usd=usd)
     
    else:
        user_id = session["user_id"]
        username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]["username"]
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        
        return render_template("settings.html", username=username, cash=cash, usd=usd)
