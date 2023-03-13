from flask import Flask
from flask import render_template, redirect, url_for, flash
from sqlalchemy.exc import IntegrityError
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, EmailField, PasswordField, SelectField, URLField, TimeField
from wtforms.validators import DataRequired
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_login import login_required
import werkzeug.security

# Flask App and plugins setup
app = Flask(__name__)
Bootstrap(app)
app.config["SECRET_KEY"] = "F5DS4F5DSF4DS8F1VSD4FVS8DF4S8F4"
db = SQLAlchemy()
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///cafes.db"
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)


# WTF Forms creation
class Suggest(FlaskForm):
    cafe_name = StringField('Cafe Name', validators=[DataRequired()])
    map_url = URLField('Map URL', validators=[DataRequired()])
    img_url = URLField('Image URL', validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired()])
    opening_time = TimeField("Opening Time", validators=[DataRequired()])
    closing_time = TimeField("Closing Time", validators=[DataRequired()])
    has_sockets = SelectField('Availability of Power Outlets', validators=[DataRequired()],
                              choices=["❌", "🔌", "🔌🔌", "🔌🔌🔌", "🔌🔌🔌🔌", "🔌🔌🔌🔌🔌"])
    has_toilets = SelectField('Toilet Cleanliness', validators=[DataRequired()],
                              choices=["❌", "🚽", "🚽🚽", "🚽🚽🚽", "🚽🚽🚽🚽", "🚽🚽🚽🚽🚽"])
    has_wifi = SelectField('Wifi Strength', validators=[DataRequired()],
                           choices=["❌", "⭐", "⭐⭐", "⭐⭐⭐", "⭐⭐⭐⭐", "⭐⭐⭐⭐⭐"])
    can_take_calls = SelectField('Can take calls', validators=[DataRequired()],
                                 choices=["❌", "📲", "📲📲", "📲📲📲", "📲📲📲📲", "📲📲📲📲📲"])
    seats = SelectField('Seats', validators=[DataRequired()],
                        choices=["❌", "🪑", "🪑🪑", "🪑🪑🪑", "🪑🪑🪑🪑", "🪑🪑🪑🪑🪑"])
    coffee_price = SelectField('Coffee Price', validators=[DataRequired()],
                               choices=["❌", "💲💲💲💲💲", "💲💲💲💲", "💲💲💲", "💲💲", "💲"])
    submit = SubmitField()


class Login(FlaskForm):
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class Register(FlaskForm):
    name = StringField()
    email = EmailField()
    password = PasswordField()
    submit = SubmitField("Register")


# SQLAlchemy Database Setup
class Cafes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=False, nullable=False)
    map = db.Column(db.String, unique=False, nullable=False)
    image = db.Column(db.String, unique=False, nullable=False)
    loc = db.Column(db.String, unique=False, nullable=False)
    opening_time = db.Column(db.Time, unique=False, nullable=True)
    closing_time = db.Column(db.Time, unique=False, nullable=True)
    sockets = db.Column(db.String, nullable=False)
    toilets = db.Column(db.String, nullable=False)
    wifi = db.Column(db.String, nullable=False)
    calls = db.Column(db.String, nullable=False)
    seat = db.Column(db.String, nullable=False)
    price = db.Column(db.String, nullable=False)
    score = db.Column(db.Integer, nullable=False)


class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(1000))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(1000))


# Flask Login Setup
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


@login_manager.unauthorized_handler
def unauthorized():
    return redirect(url_for('community'))


# Website Routes
@app.route("/")
def home():
    db.create_all()
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route("/explore")
def explore():
    return render_template("explore.html", cafes=Cafes.query.order_by(Cafes.score.desc()).all(),
                           logged_in=current_user.is_authenticated)


# This is the login route
@app.route("/community", methods=["POST", "GET"])
def community():
    form = Login()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = db.session.query(Users).filter_by(email=email).first()
        if user:
            if werkzeug.security.check_password_hash(pwhash=user.password, password=password):
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash("incorrect Password")
        else:
            flash("No account registered with this email, please register to proceed")

    return render_template("community.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout', methods=["POST", "GET"])
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/register", methods=["POST", "GET"])
def register():
    form = Register()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        hashed_pass = werkzeug.security.generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
        new_user = Users(name=name, email=email, password=hashed_pass)
        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            flash("This email is already registered, please login")
            return redirect(url_for('community'))
        else:
            load_user(new_user)
            return redirect(url_for("home"))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


# This route is divided into 2 functions to have login as a requirement when submitting the form
@app.route("/suggest", methods=["POST"])
@login_required
def suggest_get():
    form = Suggest()
    if form.validate_on_submit():
        name = form.cafe_name.data
        map = form.map_url.data
        image = form.img_url.data
        loc = form.location.data
        opening = form.opening_time.data
        closing = form.closing_time.data
        sockets = form.has_sockets.data
        toilets = form.has_toilets.data
        wifi = form.has_wifi.data
        calls = form.can_take_calls.data
        seat = form.seats.data
        price = form.coffee_price.data
        total = 0

        if price == '💲':
            total += 5
        elif price == '💲💲':
            total += 4
        elif price == '💲💲💲':
            total += 3
        elif price == '💲💲💲💲':
            total += 2
        elif price == '💲💲💲💲💲':
            total += 1
        else:
            total += 0

        if sockets == '🔌🔌🔌🔌🔌':
            total += 5
        elif sockets == '🔌🔌🔌🔌':
            total += 4
        elif sockets == '🔌🔌🔌':
            total += 3
        elif sockets == '🔌🔌':
            total += 2
        elif sockets == '🔌':
            total += 1
        else:
            total += 0

        if toilets == '🚽🚽🚽🚽🚽':
            total += 5
        elif toilets == '🚽🚽🚽🚽':
            total += 4
        elif toilets == '🚽🚽🚽':
            total += 3
        elif toilets == '🚽🚽':
            total += 2
        elif toilets == '🚽':
            total += 1
        else:
            total += 0

        if wifi == '⭐⭐⭐⭐⭐':
            total += 5
        elif wifi == '⭐⭐⭐⭐':
            total += 4
        elif wifi == '⭐⭐⭐':
            total += 3
        elif wifi == '⭐⭐':
            total += 2
        elif wifi == '⭐':
            total += 1
        else:
            total += 0

        if calls == '📲📲📲📲📲':
            total += 5
        elif calls == '📲📲📲📲':
            total += 4
        elif calls == '📲📲📲':
            total += 3
        elif calls == '📲📲':
            total += 2
        elif calls == '📲':
            total += 1
        else:
            total += 0

        if seat == "🪑🪑🪑🪑🪑":
            total += 5
        elif seat == "🪑🪑🪑🪑":
            total += 4
        elif seat == '🪑🪑🪑':
            total += 3
        elif seat == '🪑🪑':
            total += 2
        elif seat == '🪑':
            total += 1
        else:
            total += 0

        total = round((total / 30) * 100)

        new_entry = Cafes(name=name, map=map, image=image, loc=loc, opening_time=opening, closing_time=closing,
                          sockets=sockets, toilets=toilets, wifi=wifi,
                          calls=calls, seat=seat, price=price, score=total)
        db.session.add(new_entry)
        db.session.commit()
        return redirect(url_for("explore"))
    return render_template("suggest.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/suggest", methods=["GET"])
def suggest():
    form = Suggest()
    return render_template("suggest.html", form=form, logged_in=current_user.is_authenticated)


if __name__ == "__main__":
    app.run(debug=True)
