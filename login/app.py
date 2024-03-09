from flask import Flask, render_template, redirect, request, flash, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, validators
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from flask import Flask, render_template, redirect, url_for


app = Flask(__name__)
app.config['SECRET_KEY'] = '123456'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:123456@localhost/db'  # Thay đổi đường dẫn kết nối với cơ sở dữ liệu của bạn
db = SQLAlchemy(app)

# Tạo một model cho bảng người chơi
class Players(db.Model):
    __tablename__ = 'players'
    IdPlayer = db.Column(db.Integer, primary_key=True)
    UserName = db.Column(db.String(255), nullable=False)
    UserPassWord = db.Column(db.String(255), nullable=False)
    FullName = db.Column(db.String(255))
    PhoneNumber = db.Column(db.String(255))
    Address = db.Column(db.String(255))
    Email = db.Column(db.String(255))
    Date = db.Column(db.DateTime)
    TurnsOfPlay = db.Column(db.Integer)

# Form cho trang đăng nhập
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[validators.DataRequired()])
    password = PasswordField('Password', validators=[validators.DataRequired()])
    submit = SubmitField('Login')

# Form cho trang đăng ký
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[validators.DataRequired()])
    password = PasswordField('Password', validators=[
        validators.DataRequired(),
        validators.EqualTo('confirm_password', message='Passwords must match')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[validators.DataRequired()])
    submit = SubmitField('Register')
@app.route("/login/facebook")
def login_with_facebook():
    if not facebook.authorized:
        return redirect(url_for("facebook.login"))
    resp = facebook.get("/me?fields=id,name,email")
    assert resp.ok, resp.text
    email = resp.json()["email"]
    # Xử lý việc đăng nhập với email từ Facebook ở đây
    return redirect("/")  # Redirect sau khi đăng nhập thành công
# Khởi tạo blueprint cho đăng nhập bằng Google
google_bp = make_google_blueprint(
    client_id="your-google-client-id",
    client_secret="your-google-client-secret",
    scope=["profile", "email"],
    redirect_to="google_login"
)
app.register_blueprint(google_bp, url_prefix="/login")

# Route cho việc đăng nhập bằng Google
@app.route("/login/google")
def login_with_google():
    if not google.authorized:
        return redirect(url_for("google.login"))
    resp = google.get("/oauth2/v2/userinfo")
    assert resp.ok, resp.text
    email = resp.json()["email"]
    # Xử lý việc đăng nhập với email từ Google ở đây
    return redirect("/")  # Redirect sau khi đăng nhập thành công

# Route cho trang đăng nhập
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        player = Players.query.filter_by(UserName=username).first()
        if player and check_password_hash(player.UserPassWord, password):
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

# Route cho trang đăng ký
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        existing_user = Players.query.filter_by(UserName=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
        else:
            new_player = Players(UserName=username, UserPassWord=generate_password_hash(password))
            db.session.add(new_player)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)
@app.route('/logout')
# Route cho trang chính
def logout():
    # Điều hướng đến trang đăng nhập
    return redirect(url_for('login'))
@app.route('/')
def index():
    return render_template('index.html')
if __name__ == '__main__':
    app.run(debug=True)
