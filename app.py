# app.py
import os, json
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user

app = Flask(__name__)

# Chave secreta: OBRIGATORIA para usar sessoes, usar chave segura em producao
app.secret_key = 'sua_chave_secreta_muito_segura'

# Configura sessão permanente (remember me)
app.permanent_session_lifetime = timedelta(minutes=10) #(days=7)

# Configuracao do Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # rota para onde redirecionar se não autenticado
login_manager.login_message = "Voce precisa se autenticar para acessar esta página"
login_manager.login_message_category = "warning"

# ---

# Usuarios de exemplo (TODO: aqui simulando um banco de dados)
users = {"admin": {"password": "123"},"demo": {"password": "demo"}}

# Modelo de usuario simples
class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id) if user_id in users else None

# ---

# se requer autenticacao, envia pagina da requisicao original para a tela de login
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            # passa URL original como parâmetro
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function

# Rota inicial (publica)
@app.route("/")
def home():
    return render_template('home.html')

# Rota about (publica)
@app.route("/aboutme")
def aboutme():
    return render_template('aboutme.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():

    # Se o metodo for POST, o usuario esta tentando se logar
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = request.form.get('remember')

        # Simulacao de autenticacao com credenciais
        if username in users and users[username]["password"] == password:
            user = User(username)
            login_user(user)
            if remember:
                session.permanent = True
            else:
                session.permanent = False
            flash("Login realizado com sucesso!", "success")
            return redirect(request.form.get('next') or url_for('home'))
        else:
            flash('Usuário ou senha inválidos.', 'danger')
            return render_template('login.html', error=True)

    # Se o metodo for GET, apenas exibe a pagina de login
    next_page = request.args.get("next")  # captura qual pagina que tentou acessar
    return render_template('login.html', error=False, next_page=next_page)

# Rota chavenfce (publica)
@app.route("/chavenfe")
def chavenfe():
    return render_template('chave_nfe.html')

# Rota consulta nfe (publica)
@app.route("/consultanfe")
def consultanfe():
  
    # carrega lista de consultas
    with open(os.path.join(app.static_folder, 'consultanfe.json'), 'r', encoding='utf-8') as f:
        lista_nfe = json.load(f)
    return render_template('consulta_nfe.html', nfes=lista_nfe)

# Rota protegida
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user.id)

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você encerrou a sua sessão.', 'info')
    return render_template('home.html')

if __name__ == '__main__':
    # identifica se esta sendo executado no ambiente Vercel
    vercel_keys = ['VERCEL', 'VERCEL_ENV']
    is_vercel = any(key in os.environ for key in vercel_keys)
    app.run(debug=not is_vercel)
