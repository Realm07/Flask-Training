from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///memory.db"
app.secret_key = "panda"
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(50), nullable = False)
    password = db.Column(db.String(50), nullable = False)
    email = db.Column(db.String(50), nullable = False)

@app.route("/")
def home():
    return "<p>Home</p>"

@app.route("/user/register", methods = ["GET", "POST"])
def register_user():
    if request.method == "POST":
        uname = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        if not uname or not password:
            return {"error": "Name and role are required"}, 400

        user = User()
        user.name = uname
        user.password = password
        user.email = email

        db.session.add(user)
        db.session.commit()

        return redirect(url_for("fetch_user"))
    return render_template("user/userRegister.html")

@app.get("/user/show")
def fetch_user():
    users = User.query.all()
    return render_template("user/userShow.html",users = users)    

@app.route("/user/login", methods=["GET", "POST"])
def login():
    allowed_user = {"arsh ahmad": "admin"}

    if "user" in session:
        user = User.query.filter(User.name == session["user"]).first()
        if session["user"] in allowed_user and allowed_user[session["user"]] == "admin":
            return render_template("dashboard.html", uname=session["user"])
        else:
            return render_template("userPage.html", uname=session["user"])

    if request.method == "POST":
        uname = request.form.get("name")
        password = request.form.get("password")

        
        user = User.query.filter(User.name == uname).first()

        
        if str(uname).lower() in allowed_user and allowed_user[str(uname).lower()] == "admin":
            if user and user.password == password:
                session["user"] = uname
                return render_template("dashboard.html", uname=session["user"])
            else:
                return render_template("user/userLogin.html", error="Invalid credentials")
        else:
            if user and user.password == password:
                session["user"] = uname
                return render_template("userPage.html", uname=session["user"])
            else:
                return render_template("user/userLogin.html", error="Invalid credentials")

    return render_template("user/userLogin.html", error="Unauthorized user")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all() 
    app.run(debug=True)   