import uuid
from flask import render_template, redirect, url_for, abort, flash, request, \
    current_app, make_response, send_from_directory, send_file, jsonify
import os
from os import listdir
from os.path import isfile, join
from werkzeug import secure_filename
from flask_login import login_required, current_user
from flask_ckeditor import upload_fail, upload_success
from flask_sqlalchemy import get_debug_queries
from . import main
from .forms import EditProfileForm, EditProfileAdminForm, PostForm, \
    CommentForm, UploadForm, MultipleUploadForm, SearchForm
from .. import db
from ..models import Permission, Role, User, Post, Comment, Like
from ..decorators import admin_required, permission_required

@main.after_app_request
def after_request(response):
    for query in get_debug_queries():
        if query.duration >= current_app.config['FLASKY_SLOW_DB_QUERY_TIME']:
            current_app.logger.warning(
                'Slow query: %s\nParameters: %s\nDuration: %fs\nContext: %s\n'
                % (query.statement, query.parameters, query.duration,
                query.context))
    return response


@main.route('/', methods=['GET', 'POST'])
@main.route('/index', methods=['GET', 'POST'])
def index():
    form = PostForm()
    if current_user.can(Permission.WRITE_ARTICLES) and \
            form.validate_on_submit():
        post = Post(body=form.body.data, author=current_user._get_current_object())
        db.session.add(post)
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    show_followed = False
    if current_user.is_authenticated:
        show_followed = bool(request.cookies.get('show_followed', ''))
    if show_followed:
        query = current_user.followed_posts
    else:
        query = Post.query
    pagination = query.order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    return render_template('index.html', form=form, posts=posts,
                            show_followed=show_followed, pagination=pagination)

@main.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    pagination = user.posts.order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    return render_template('user.html', user=user, posts=posts, pagination=pagination)

@main.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        db.session.add(current_user)
        flash('Your profile has been updated.')
        return redirect(url_for('.user', username=current_user.username))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', form=form)

@main.route('/edit-profile/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(id):
    user = User.query.get_or_404(id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = Role.query.get(form.role.data)
        user.name = form.name.data
        user.location = form.location.data
        user.about_me = form.about_me.data
        db.session.add(user)
        flash(f'{user.username}\'s profile has been updated.')
        return redirect(url_for('.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.name
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('edit_profile.html', form=form, user=user)

@main.route('/post/<int:id>', methods=['GET', 'POST'])
def post(id):
    post = Post.query.get_or_404(id)
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(body=form.body.data,
                          post=post,
                          author=current_user._get_current_object())
        db.session.add(comment)
        flash('Your comment has been published.')
        return redirect(url_for('.post', id=post.id, page=-1))
    page = request.args.get('page', 1, type=int)
    if page == -1:
        page = (post.comments.count() - 1) // \
        current_app.config['FLASKY_COMMENTS_PER_PAGE'] + 1
    pagination = post.comments.order_by(Comment.timestamp.asc()).paginate(
        page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
        error_out=False)
    comments = pagination.items
    return render_template('post.html', posts=[post], form=form,
                            comments=comments, pagination=pagination)

@main.route('/post/delete/<int:id>', methods=['GET', 'POST'])
def delete_post(id):
    post = Post.query.get_or_404(id)
    post.delete()
    flash("Delete post complete")
    return redirect(url_for('.index'))



@main.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    post = Post.query.get_or_404(id)
    if current_user != post.author and \
            not current_user.can(Permission.ADMINISTER):
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.body = form.body.data
        db.session.add(post)
        flash('The post has been updated.')
        return redirect(url_for('.post', id=post.id))
    form.body.data = post.body
    return render_template('edit_post.html', form=form)

@main.route('/follow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    if current_user.is_following(user):
        flash('You are already following this user.')
        return redirect(url_for('.user', username=username))
    current_user.follow(user)
    flash('You are now following %s.' % username)
    return redirect(url_for('.user', username=username))


@main.route('/unfollow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    if not current_user.is_following(user):
        flash('You are not following this user.')
        return redirect(url_for('.user', username=username))
    current_user.unfollow(user)
    flash('You are not following %s anymore.' % username)
    return redirect(url_for('.user', username=username))


@main.route('/followers/<username>')
def followers(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followers.paginate(
        page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
        error_out=False)
    follows = [{'user': item.follower, 'timestamp': item.timestamp}
               for item in pagination.items]
    return render_template('followers.html', user=user, title="Followers of",
                           endpoint='.followers', pagination=pagination,
                           follows=follows)


@main.route('/followed-by/<username>')
def followed_by(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followed.paginate(
        page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
        error_out=False)
    follows = [{'user': item.followed, 'timestamp': item.timestamp}
               for item in pagination.items]
    return render_template('followers.html', user=user, title="Followed by",
                           endpoint='.followed_by', pagination=pagination,
                           follows=follows)

@main.route('/all')
@login_required
def show_all():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_followed', '', max_age=30*24*60*60)
    return resp


@main.route('/followed')
@login_required
def show_followed():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_followed', '1', max_age=30*24*60*60)
    return resp

@main.route('/moderate')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate():
    page = request.args.get('page', 1, type=int)
    pagination = Comment.query.order_by(Comment.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
        error_out=False)
    comments = pagination.items
    return render_template('moderate.html', comments=comments,
                            pagination=pagination, page=page)


@main.route('/moderate/enable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_enable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = False
    db.session.add(comment)
    return redirect(url_for('.moderate',
                            page=request.args.get('page', 1, type=int)))


@main.route('/moderate/disable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_disable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = True
    db.session.add(comment)
    return redirect(url_for('.moderate',
                            page=request.args.get('page', 1, type=int)))


@main.route('/confirm')
@login_required
@admin_required
def confirm():
    page = request.args.get('page', 1, type=int)
    #tmp = User.query.order_by(User.confirmed.asc())
    pagination = User.query.order_by(User.member_since.desc()).paginate(
        page, per_page=current_app.config['FLASKY_REQUEST_PER_PAGE'],
        error_out=False)
    requests = pagination.items
    return render_template('confirm.html', requests=requests,
                            pagination=pagination, page=page)


@main.route('/confirm/enable/<int:id>')
@login_required
@admin_required
#@login.user_loader
def confirm_enable(id):
    conf = User.query.get_or_404(id)
    conf.confirm_acc()
    return redirect(url_for('.confirm', page=request.args.get('page', 1, type=int)))


@main.route('/confirm/disable/<int:id>')
@login_required
@admin_required
def confirm_disable(id):
    conf = User.query.get_or_404(id)
    conf.confirm_acc()
    return redirect(url_for('.confirm', page=request.args.get('page', 1, type=int)))


@main.route('/confirm/delete/<int:id>')
@login_required
@admin_required
def delete(id):
    conf = User.query.get_or_404(id)
    conf.delete()
    return redirect(url_for('.confirm', page=request.args.get('page', 1, type=int)))
    
@main.route('/confirm/set_moderate/<int:id>')
@login_required
@admin_required
def set_moderate(id):
    conf = User.query.get_or_404(id)
    conf.set_moderate()
    return redirect(url_for('.confirm', page=request.args.get('page', 1, type=int)))
    

@main.route('/ckeditor')
@login_required
@admin_required
def ckeditor():
    form = RichTextForm()
    return render_template('ckeditor.html',form = form)
    
@main.route('/about')
def about():
    user = User.query.get(1)
    #page = request.args.get('page', 1, type=int)
    #pagination = user.posts.order_by(Post.timestamp.desc()).paginate(
    #    page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
    #    error_out=False)
    #posts = pagination.items
    return render_template('about.html', user=user)#, posts=posts, pagination=pagination)
    
@main.route('/uploads', methods = ['POST', 'GET'])
@login_required
@admin_required
def uploads():
    form = UploadForm()
    onlyfiles = [f for f in listdir(current_app.config['UPLOAD_FOLDER']) if isfile(join(current_app.config['UPLOAD_FOLDER'], f))]
    owners = {}
    for filename in onlyfiles:
        own = filename.split('|')[0]
        #user = User.query.filter_by(username=username).first_or_404()
        owners[filename.split('|')[1]] = User.query.filter_by(username=own).first()
    if form.validate_on_submit():
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = current_user.username + "|" + secure_filename(file.filename)
            #if os.path.exists(os.path.join(current_app.config['UPLOAD_FOLDER'], filename)):
            #    filename = str(uuid.uuid4()) + filename
            path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            file.save(path)
            flash(f'{filename} Upload success.')
            return redirect(url_for('main.uploads'))
    page_head = "Uploaded files"
    return render_template('uploads.html', form=form, owners=owners)
    
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in current_app.config['ALLOWED_EXTENSIONS']
           
           
@main.route('/multiple_uploads', methods = ['POST', 'GET'])
@login_required
@admin_required
def multiple_uploads():
    form = MultipleUploadForm()
    owners = get_list_files(filter_file = "")
    #print(owners)
    if form.validate_on_submit():
        complete = 0
        error = 0
        if 'file' not in request.files:
            flash('This field is required.')
            return redirect(url_for('main.multiple_uploads'))
        for file in request.files.getlist('file'): #file = request.files['file']
            if file:
                filename = current_user.username + "|" + secure_filename(file.filename)
                #if os.path.exists(os.path.join(current_app.config['UPLOAD_FOLDER'], filename)):
                #    filename = str(uuid.uuid4()) + filename
                path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                flash(f'{filename} upload success.')
                complete += 1
                file.save(path)
            else:
                flash(f'Invalid file type: {file.filename}')
                error += 1
                return redirect(url_for('main.multiple_uploads'))
        flash(f'Upload success. [Total]: {complete+error}, [Complete]: {complete}, [Error]: {error}')
        return redirect(url_for('main.multiple_uploads'))
    return render_template('uploads.html', form=form, owners=owners)

def get_list_files(filter_file):
    if filter_file == "":
        onlyfiles = [f for f in listdir(current_app.config['UPLOAD_FOLDER']) if isfile(join(current_app.config['UPLOAD_FOLDER'], f)) and allowed_file(f)]
    else:
        onlyfiles = [f for f in listdir(current_app.config['UPLOAD_FOLDER']) if isfile(join(current_app.config['UPLOAD_FOLDER'], f)) and allowed_file(f) and filter_file.lower() in f.lower()]
    owners = {}
    for filename in onlyfiles:
        own = filename.split('|')[0]
        #user = User.query.filter_by(username=username).first_or_404()
        if not User.query.filter_by(username=own).first():
            tmp = User.query.filter_by(id=1).first()
        else:
            tmp = User.query.filter_by(username=own).first()
        owners[filename.split('|')[1]] = tmp
    return owners


@main.route('/ckeditor_uploads', methods = ['POST'])
@login_required
def ckeditor_uploads():
    file = request.files.get('upload')
    if allowed_file(file.filename):
        filename = str(uuid.uuid4()) + "." + file.filename.rsplit('.', 1)[1]
        path = os.path.join(current_app.config['UPLOAD_FOLDER'], current_user.username)
        if not os.path.exists(path):
            os.makedirs(path)
        file.save(os.path.join(path, filename))
        url = url_for('main.view', filename=filename, username=current_user.username)
        return upload_success(url, filename=filename)
    else:
        return upload_fail(message='Image only!')


@main.route('/view/<path:filename>?<username>', methods=['GET', 'POST'])
def view(username, filename):
    uploads = os.path.join(current_app.config['UPLOAD_FOLDER'], username)
    return send_from_directory(directory=uploads, filename=filename)


@main.route('/download/<owner>?<path:filename>', methods=['GET', 'POST'])
def download(filename, owner):
    if filename:
        filename = owner + '|' + filename
        uploads = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(uploads):
            return send_file(uploads, as_attachment=True)
        else:
            flash(f'Not Found: {filename}')
            return redirect(url_for('main.download_file'))
    return redirect(url_for('main.download_file'))

@main.route('/download', methods=['POST', 'GET'])
def download_file():
    form = SearchForm()
    filter_file = ""
    if form.validate_on_submit():
        filter_file  = form.search.data
    owners = get_list_files(filter_file)
    return render_template('download.html', form=form, owners=owners)

@main.route('/download/delete/<owner>?<path:filename>', methods=['GET', 'POST'])
def delete_file(owner, filename):
    if filename:
        filename = owner + '|' + filename
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        os.remove(file_path)
        flash(f'Delete {filename} complete')
    else:
        flash('Error!')
    return redirect(url_for('main.download_file'))

    
@main.route('/like/<post_id>', methods = ['POST'])
def like(post_id):
    post = Post.query.filter_by(id=post_id).first()
    if not post is None:
        current_user.like(post)
        return jsonify(liked_count=post.liked_post.count())
    return redirect(url_for('.index'))

@main.route('/rank')
def rank():
    page = request.args.get('page', 1, type=int)
    posts = Post.query.all()
    posts.sort(reverse=True, key=condition)
    user = posts[:5]
    return render_template('rank.html', requests=user, page=page)
def condition(post):
    return str(post.liked_post.count()) + str(post.timestamp)