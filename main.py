from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import ForeignKey
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, LoginForm, RegisterForm, CreateCommentForm
from flask_gravatar import Gravatar
from sqlalchemy.exc import SQLAlchemyError
from functools import wraps
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL_1", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


app.secret_key = "r-27hssA5k<R<<>66"
login_manager = LoginManager()
login_manager.init_app(app)


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


##CONFIGURE TABLES


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    blog_post = db.relationship("BlogPost", backref="id_author")
    comments = db.relationship("Comment", backref="id_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, ForeignKey("users.id"))
    blogpost_id = db.relationship("Comment", backref="id_parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, ForeignKey("users.id"))
    parent_post = db.Column(db.Integer, ForeignKey("blog_posts.id"))

db.create_all()
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        new_user = User()
        pw_to_encrypt = form.password.data
        new_user.password = generate_password_hash(password=pw_to_encrypt, method="pbkdf2:sha256", salt_length=8)
        new_user.name = form.name.data
        new_user.email = form.email.data
        try:
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
        except SQLAlchemyError:
            flash("This user already exists.")
            return redirect(url_for('login'))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter(User.email == form.email.data)
        user_auth = user.first()
        try:
            pw_hash = user_auth.password
        except AttributeError:
            pw_hash = None
        if not user_auth:
            flash("Email does not exist in database.")
            return redirect(url_for("login"))
        elif not check_password_hash(pwhash=pw_hash, password=form.password.data):
            flash("Wrong password.")
            return redirect(url_for("login"))
        else:
            login_user(user_auth)
            return redirect(url_for("get_all_posts"))
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comments = db.session.query(Comment).filter(Comment.parent_post == post_id)
    form = CreateCommentForm()
    if form.validate_on_submit():
        if current_user.is_active:
            text = form.body.data.replace('<p>', '')
            text_stripped = text.replace('</p>', '')
            new_comment = Comment(
                body=text_stripped,
                author=current_user.name,
                parent_post=requested_post.id,
                author_id=current_user.id,
            )
            db.session.add(new_comment)
            db.session.commit()
        else:
            flash("Please login in order to make a comment.")
            return redirect(url_for('login'))

    form.body.data = ""
    return render_template("post.html", post=requested_post,  form=form, all_comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y"),
            author_id=current_user.id,
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = post.author
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@login_manager.user_loader
def load_user(id):
    return User.query.get(id)


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=8080)
