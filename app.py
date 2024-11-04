from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
from base64 import b64encode

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///zadachi.db'
app.config['SQLALCHEMY_BINDS'] = {'users': 'sqlite:///users.db'}
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads/'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Модель тега
class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

# Таблица связывания задач и тегов
post_tag = db.Table('post_tag',
    db.Column('post_id', db.Integer, db.ForeignKey('post.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)

# Обновление модели задачи для поддержки тегов
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300), nullable=False)
    zad = db.Column(db.LargeBinary, nullable=False)
    resh1 = db.Column(db.LargeBinary, nullable=False)
    resh2 = db.Column(db.LargeBinary, nullable=True)
    resh3 = db.Column(db.LargeBinary, nullable=True)
    resh4 = db.Column(db.LargeBinary, nullable=True)
    resh5 = db.Column(db.LargeBinary, nullable=True)
    level = db.Column(db.Integer, nullable=False)
    tags = db.relationship('Tag', secondary=post_tag, backref=db.backref('posts', lazy='dynamic'))

# Модель пользователя
class User(UserMixin, db.Model):
    __bind_key__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'admin', 'teacher', 'student'





@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Неправильные имя пользователя или пароль.')

    return render_template('login.html')


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    # Логика выхода пользователя
    logout_user()  # вызов функции из Flask-Login
    return redirect(url_for('index'))  # перенаправление на главную страницу


@app.route('/register_teacher', methods=['GET', 'POST'])
@login_required
def register_teacher():
    if current_user.role != 'admin':
        flash('Доступ запрещен.')
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password, role='teacher')

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Учитель успешно добавлен.')
            return redirect(url_for('index'))
        except Exception as e:
            flash(f'Ошибка при добавлении учителя: {e}')

    return render_template('register_teacher.html')


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if current_user.role not in ['admin', 'teacher']:
        flash('Только администраторы и учителя могут добавлять задачи.')
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form['title']
        level = request.form['level']
        tags_input = request.form['tags'].split(',')

        zad = request.files['zad'].read()
        resh1 = request.files['resh1'].read()
        resh2 = request.files['resh2'].read() if 'resh2' in request.files else None
        resh3 = request.files['resh3'].read() if 'resh3' in request.files else None
        resh4 = request.files['resh4'].read() if 'resh4' in request.files else None
        resh5 = request.files['resh5'].read() if 'resh5' in request.files else None

        # Создаем задачу
        post = Post(title=title, zad=zad, resh1=resh1, resh2=resh2, resh3=resh3, resh4=resh4, resh5=resh5, level=level)

        # Обработка тегов
        for tag_name in tags_input:
            tag_name = tag_name.strip().lower()
            if tag_name:
                tag = Tag.query.filter_by(name=tag_name).first()
                if not tag:
                    tag = Tag(name=tag_name)
                    db.session.add(tag)
                post.tags.append(tag)

        try:
            db.session.add(post)
            db.session.commit()
            return redirect('/')
        except Exception as e:
            return f'При добавлении задачи произошла ошибка: {e}'

    return render_template('create.html')



# Главная страница
@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/delete/<int:id>', methods=['POST'])
def delete_post(id):
    post = Post.query.get_or_404(id)

    try:
        db.session.delete(post)
        db.session.commit()
        return redirect('/posts')
    except Exception as e:
        return f'Ошибка при удалении задачи: {e}'





# Страница со всеми задачами
@app.route('/posts', methods=["GET"])
def posts():
    sort_by = request.args.get('sort_by', 'id')
    order = request.args.get('order', 'asc')
    filter_tags = request.args.getlist('tags')

    query = Post.query

    if filter_tags:
        query = query.join(Post.tags).filter(Tag.name.in_(filter_tags))

    if sort_by == 'title':
        query = query.order_by(Post.title.asc() if order == 'asc' else Post.title.desc())
    elif sort_by == 'level':
        query = query.order_by(Post.level.asc() if order == 'asc' else Post.level.desc())
    else:
        query = query.order_by(Post.id.asc())

    posts = query.all()
    all_tags = Tag.query.all()  # Для отображения всех доступных тегов

    return render_template('posts.html', posts=posts, sort_by=sort_by, order=order, all_tags=all_tags)




@app.route('/post/<int:id>')
def show_post_detail(id):
    post = Post.query.get_or_404(id)

    def safe_b64encode(data):
        return b64encode(data).decode('utf-8') if data else None

    zad_base64 = safe_b64encode(post.zad)
    resh1_base64 = safe_b64encode(post.resh1)
    resh2_base64 = safe_b64encode(post.resh2)
    resh3_base64 = safe_b64encode(post.resh3)
    resh4_base64 = safe_b64encode(post.resh4)
    resh5_base64 = safe_b64encode(post.resh5)

    return render_template('post_detail.html', post=post, zad_base64=zad_base64, resh1_base64=resh1_base64, resh2_base64=resh2_base64, resh3_base64=resh3_base64, resh4_base64=resh4_base64,resh5_base64=resh5_base64)





# Страница "О проекте"
@app.route('/about')
def about():
    return render_template('about.html')


# Функция для отображения изображений в формате Base64
def to_base64(binary_data):
    return b64encode(binary_data).decode('utf-8')


# Добавление функции в шаблон
app.jinja_env.filters['to_base64'] = to_base64


# Создание папки для загрузки файлов, если она не существует
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

app.run(debug=False)

