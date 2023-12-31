from flask import render_template, redirect, url_for, flash, request, make_response, jsonify
from flask_login import login_user, login_required, logout_user, current_user

from application import app
from application.models import *
from application.forms import *
from application.utils import save_image

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()
        if user and password == user.password:
            login_user(user)
            return redirect(url_for('profile', username=username))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html', title="Login", form=form)

@app.route('/logout')
@login_required  
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/<string:username>')
@login_required
def profile(username):
    posts = current_user.posts
    reverse_posts = posts[::-1]
    return render_template('profile.html', title=f'{current_user.fullname} Profile', posts=reverse_posts)

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    form = CreatePostForm()

    if form.validate_on_submit():
        post = Post(
            author_id = current_user.id,
            caption = form.caption.data
        )
        post.photo = save_image(form.post_pic.data)
        db.session.add(post)
        db.session.commit()
        flash('your image has been posted 💖!', 'success')

    page = request.args.get('page', 1, type=int)
    posts = Post.query.filter_by(author_id = current_user.id).order_by(Post.post_date.desc()).paginate(page=page, per_page=3)

    return render_template('index.html', title='Home', form=form, posts=posts)

@app.route('/signup', methods=['POST', 'GET'])
def signup():
    
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = SignUpForm()

    if form.validate_on_submit():
        username = form.username.data
        fullname = form.fullname.data
        email = form.email.data
        password = form.password.data

        user = User(
            username=username,
            fullname=fullname,
            email=email,
            password=password
        )
        
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('profile', username=username))
        

    return render_template('signup.html', title='Signup', form=form)

@app.route('/about')
def about():
    return render_template('about.html', title='About')

@app.route('/editProfile', methods=['GET', 'POST'])
@login_required
def editProfile():
    form = EditProfileForm()

    if form.validate_on_submit():
        user = User.query.get(current_user.id)
        if form.username.data != user.username:
            user.username = form.username.data

        user.fullname = form.fullname.data
        user.bio = form.bio.data

        if form.profile_pic.data != user.profile_pic:
            # user.profile_pic = form.profile_pic.data
            pass

        db.session.commit()
        flash('Profile update', 'success')
        return redirect(url_for('profile', username=current_user.username))
    
    form.username.data = current_user.username
    form.fullname.data = current_user.fullname
    form.bio.data = current_user.bio

    return render_template('editprofile.html', title=f'Edit {current_user.username}Profile',form=form)

@app.route('/resetPassword')
@login_required
def resetPassword():
    form = ResetPasswordForm()
    return render_template('resetPassword.html', title='Reset Password', form=form)

@app.route('/forgotPassword')
def forgotPassword():
    form = ForgotPasswordForm()
    return render_template('forgotPassword.html', title='Forgot Password', form=form)

@app.route('/editPost')
@login_required
def editPost():
    form = EditPostForm()
    return render_template('editPost.html', title='Edit Post', form=form)

@app.route('/like', methods=['GET', 'POST'])
@login_required
def like():
    data = request.json
    post_id = int(data['postId'])
    like = Like.query.filter_by(user_id = current_user.id, post_id = post_id).first()

    if not like:
        like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(like)
        db.session.commit()
        return make_response(jsonify({"status" : True}), 200)
    
    db.session.delete(like)
    db.session.commit()
    return make_response(jsonify({"status" : False}), 200)