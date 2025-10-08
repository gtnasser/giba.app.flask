# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from datetime import timedelta

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

# Usuarios de exemplo (TODO: aqui simulando um banco de dados)
users = {"admin": {"password": "123"},"demo": {"password": "demo"}}

# Modelo de usuario simples
class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id) if user_id in users else None

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
            next_page = request.args.get("next")  # volta para a pagina que tentou acessar
            return redirect(next_page or url_for("home"))
        else:
            flash('Usuário ou senha inválidos.', 'danger')
            return render_template('login.html', error=True)

    # Se o metodo for GET, apenas exibe a pagina de login
    return render_template('login.html', error=False)

# Rota about (publica)
@app.route("/chavenfe")
def chavenfe():
    return render_template('chave_nfe.html')

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
    # Debug=True e bom para desenvolvimento. Use False em produção!
    app.run(debug=True)
