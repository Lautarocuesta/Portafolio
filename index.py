from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Inicialización de la aplicación Flask
app = Flask(__name__, template_folder='app/templates')


# Configuración de la base de datos Clever Cloud
app.config['SECRET_KEY'] = 'your_secret_key'  # Reemplázalo con una clave secreta segura
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://urzsjtckpsfqpdnl:e9AWhayNOrMr0FbgGHtf@bbixqs0e1wg17v5zentb-mysql.services.clever-cloud.com:3306/bbixqs0e1wg17v5zentb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializar extensiones
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
migrate = Migrate(app, db)

# Modelo para el usuario
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

# Formulario de registro
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already registered.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/')
def index():
    return render_template('base.html')

# Ruta de registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Account created for {form.username.data}!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Ruta de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=True)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

# Ruta para cerrar sesión
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

# Ruta para editar el portafolio (solo accesible para usuarios logueados)
@app.route('/edit_portfolio')
@login_required
def edit_portfolio():
    return render_template('edit_portfolio.html')

# Crea las tablas de la base de datos
@app.before_request
def create_tables():
    # Crea las tablas necesarias en la base de datos si no existen
    db.create_all()

# Gestión de usuarios logueados
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Iniciar la aplicación
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Crea las tablas necesarias si no existen
    app.run(debug=True)
