from flask import Flask, render_template, redirect, session, request, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Feedback
from forms import RegistrationForm, LoginForm, FeedbackForm
from flask_migrate import Migrate

app = Flask(__name__)
app.secret_key = 'okieeee'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///feedback'
db.init_app(app)


migrate = Migrate(app, db)


@app.route('/')
def index():
    return redirect('/register')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(
            username=form.username.data,
            password=hashed_password,
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data
        )
        db.session.add(new_user)
        db.session.commit()
        session['username'] = new_user.username
        flash('Registration successful!', 'success')
        return redirect(f'/users/{new_user.username}')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(f'/users/{user.username}')
        flash('Login failed. Check your username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/users/<username>')
def user_profile(username):
    if 'username' not in session:
        return redirect('/login')
    
    if session['username'] != username:
        return redirect('/')

    user = User.query.get(username)
    feedbacks = Feedback.query.filter_by(username=username).all()
    return render_template('user_profile.html', user=user, feedbacks=feedbacks)

@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def add_feedback(username):
    if 'username' not in session or session['username'] != username:
        return redirect('/login')

    form = FeedbackForm()
    if form.validate_on_submit():
        new_feedback = Feedback(
            title=form.title.data,
            content=form.content.data,
            username=username
        )
        db.session.add(new_feedback)
        db.session.commit()
        flash('Feedback added!', 'success')
        return redirect(f'/users/{username}')

    return render_template('add_feedback.html', form=form)

@app.route('/feedback/<int:feedback_id>/update', methods=['GET', 'POST'])
def update_feedback(feedback_id):
    feedback = Feedback.query.get(feedback_id)
    if not feedback or feedback.username != session.get('username'):
        return redirect('/')

    form = FeedbackForm(obj=feedback)
    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data
        db.session.commit()
        flash('Feedback updated!', 'success')
        return redirect(f'/users/{feedback.username}')

    return render_template('update_feedback.html', form=form)

@app.route('/feedback/<int:feedback_id>/delete', methods=['POST'])
def delete_feedback(feedback_id):
    feedback = Feedback.query.get(feedback_id)
    if feedback and feedback.username == session.get('username'):
        db.session.delete(feedback)
        db.session.commit()
        flash('Feedback deleted!', 'success')
    return redirect(f'/users/{feedback.username}')

if __name__ == '__main__':
    app.run(debug=True)
