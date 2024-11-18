from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField,BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash

# Inicialización de la aplicación Flask
app = Flask(__name__, template_folder='app/templates')

# Configuración de la base de datos Clever Cloud
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:2612@localhost:3306/Portafolio'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Inicializar extensiones
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
migrate = Migrate(app, db)

# Modelo para el usuario
# Definir el formulario de inicio de sesión
class LoginForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Iniciar sesión')

# Simulación de base de datos de usuarios (en un caso real, usarías SQLAlchemy o algo similar)
class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password

users_db = [User('admin', '2612')]

# Función de autenticación
def authenticate_user(username, password):
    user = next((user for user in users_db if user.username == username), None)
    if user and check_password_hash(user.password, password):
        return user
    return None

# Ruta de inicio
@app.route('/index')
def index():
    return render_template('base.html')




# Ruta de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = authenticate_user(form.username.data, form.password.data)
        if user:
            flash('Inicio de sesión exitoso', 'success')
            return redirect(url_for('index'))  # Redirigir a la página principal
        else:
            flash('Usuario o contraseña incorrectos', 'danger')
    return render_template('base.html', form=form)


# Crea las tablas de la base de datos
@app.before_request
def create_tables():
    db.create_all()

# Gestión de usuarios logueados
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Iniciar la aplicación
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
