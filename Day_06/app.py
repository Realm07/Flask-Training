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

class Post(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(50), nullable = False)
    content = db.Column(db.Text, nullable = False)
    userid = db.Column(db.String(50), db.ForeignKey("user.id"))

@app.route("/")
def home():
    return "<h1>Home Page</h1>"

@app.route("/user/register", methods=["GET","POST"])
def add_user():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter(User.name==name).first()
        if not user:
            user = User()
            user.name = str(name).lower()
            user.email = str(email)
            user.password = str(password)

            db.session.add(user)
            db.session.commit()
            return redirect(url_for("fetch_user"))
        else:
            return render_template("/user/userRegister.html", error="User already exists!")
    return render_template("/user/userRegister.html", error="")

@app.get("/user/show")
def fetch_user():
    users = User.query.all()
    return render_template("user/userShow.html",users = users)


if __name__ == "__main__":
    with app.app_context():
        db.create_all() 
    app.run(debug=True)  