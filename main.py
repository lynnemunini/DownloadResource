from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
# Generate secret_key using:
# python -c 'import secrets; print(secrets.token_hex())'

app.config['SECRET_KEY'] = 'b08a59ed02e699f946eaf7124baef4c6705e575455298047386c307d675de110'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
# Configure for login object for login
login_manager.init_app(app)

# Create a user_loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
# db.create_all()



@app.route('/', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        # Check database for email address
        user = User.query.filter_by(email=email).first() 
        if user:
            flash("You have an existing account. Login instead.")
            return redirect(url_for("login"))
        else:
                password = request.form.get('password')
                password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
                new_user = User(email=email, password = password, name = name)
                db.session.add(new_user)
                db.session.commit()
                #Log in and authenticate user after adding details to database.
                login_user(new_user)
                return redirect(url_for("secrets"))
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password_put = request.form.get('password')
        user = User.query.filter_by(email=email).first() 
        try:
            password_match = check_password_hash(user.password, password_put)
        except AttributeError:
            flash("The email does not exist. Please try again.")
            return redirect(url_for("login"))
        else:
            if password_match == False:
                flash("Incorrect password")
                return redirect(url_for("login")) 
            elif password_match:
                #Log in and authenticate user.
                login_user(user)
                # flash('You were successfully logged in')
                return redirect(url_for("secrets"))   
    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets')
# Ensure that the current user is logged in and authenticated before calling the actual view
@login_required
def secrets():
    name = current_user.name
    return render_template("secrets.html", name=name, logged_in=True)


@app.route('/download')
# Ensure that the current user is logged in and authenticated before calling the actual view
@login_required
def download():
    return send_from_directory('static/files', "doc.pdf", as_attachment=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
