import io
from flask import render_template, redirect, url_for, abort, flash, request, \
    current_app, make_response, send_from_directory, send_file, jsonify
import os
from os import listdir
from os.path import isfile, join
from werkzeug import secure_filename
from flask_login import login_required, current_user
from ..lib.flask_ckeditor import upload_fail, upload_success
from flask_sqlalchemy import get_debug_queries
from . import main
from .forms import EditProfileForm, EditProfileAdminForm, PostForm, \
    CommentForm, UploadForm, SearchForm
from .. import db
from ..models import Permission, Role, User, Post, Comment, Like, Document, Setting
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
    previous = request.args.get('previous','')
    form = PostForm()
    if current_user.is_administrator():
        current_app.config['CKEDITOR_PKG_TYPE'] = Setting.query.filter_by(name='CKEDITOR_PKG_TYPE_ADMIN').first().value
    else:
        current_app.config['CKEDITOR_PKG_TYPE'] = Setting.query.filter_by(name='CKEDITOR_PKG_TYPE_USER').first().value
    if current_user.can(Permission.WRITE_ARTICLES) and \
            form.validate_on_submit():
        post = Post(body=form.body.data, author=current_user._get_current_object())
        db.session.add(post)
        return redirect(url_for('main.index'))
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
    return render_template('index.html', form=form, posts=posts, previous=previous,
                            show_followed=show_followed, pagination=pagination)

@main.route('/user/<username>')
def user(username):
    previous = request.args.get('previous','main.index')
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    show = request.cookies.get('show', '')
    if show == 'image':
        pagination = Document.query.filter_by(author_id=user.id).filter(
                                                        Document.name.like("%.jpg") |
                                                         Document.name.like("%.png")
                                                         ).order_by(Document.name.desc()).paginate(
                                                         page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
                                                         error_out=False)
    elif show == 'files':
        pagination = Document.query.filter_by(author_id=user.id).order_by(Document.name.desc()).paginate(
                                                         page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
                                                         error_out=False)
    else:
        pagination = user.posts.order_by(Post.timestamp.desc()).paginate(
            page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
            error_out=False)
    posts = pagination.items
    return render_template('user.html', user=user, posts=posts, pagination=pagination,
                                                     previous=previous, show=show)

@main.route('/user/<username>/all')
@login_required
def user_show_all(username):
    resp = make_response(redirect(url_for('.user', username=username) + "#all"))
    resp.set_cookie('show', '', max_age=30*24*60*60)
    return resp

@main.route('/user/<username>/files')
@login_required
def user_show_files(username):
    resp = make_response(redirect(url_for('.user', username=username) + '#files'))
    resp.set_cookie('show', 'files', max_age=30*24*60*60)
    return resp

@main.route('/user/<username>/image_gallery')
@login_required
def image_gallery(username):
    resp = make_response(redirect(url_for('.user', username=username) + '#image_gallery'))
    resp.set_cookie('show', 'image', max_age=30*24*60*60)
    return resp

@main.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    previous = request.args.get('previous','main.index')
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
    return render_template('edit_profile.html', form=form, previous=previous)

@main.route('/edit-profile/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(id):
    previous = request.args.get('previous','main.index')
    user = User.query.get_or_404(id)
    if not current_user.is_administrator():
        abort(403)
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
    return render_template('edit_profile.html', form=form, user=user, previous=previous)

@main.route('/post/<int:id>', methods=['GET', 'POST'])
def post(id):
    previous = request.args.get('previous','main.index')
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
    return render_template('post.html', post=post, form=form, previous=previous,
                            comments=comments, pagination=pagination)

@main.route('/post/delete/<int:id>', methods=['GET', 'POST'])
def delete_post(id):
    post = Post.query.get_or_404(id)
    post.delete()
    flash("Delete post complete")
    return redirect(url_for('main.index'))


@main.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    previous = request.args.get('previous','main.index')
    post = Post.query.get_or_404(id)
    if current_user != post.author and \
            not current_user.can(Permission.ADMINISTER):
        abort(403)
    if current_user.is_administrator():
        current_app.config['CKEDITOR_PKG_TYPE'] = Setting.query.filter_by(name='CKEDITOR_PKG_TYPE_ADMIN').first().value
    else:
        current_app.config['CKEDITOR_PKG_TYPE'] = Setting.query.filter_by(name='CKEDITOR_PKG_TYPE_USER').first().value
    form = PostForm()
    if form.validate_on_submit():
        post.body = form.body.data
        db.session.add(post)
        flash('The post has been updated.')
        return redirect(url_for('.post', id=post.id))
    form.body.data = post.body
    return render_template('edit_post.html', form=form,  previous=previous)

@main.route('/follow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('main.index'))
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
        return redirect(url_for('main.index'))
    if not current_user.is_following(user):
        flash('You are not following this user.')
        return redirect(url_for('.user', username=username))
    current_user.unfollow(user)
    flash('You are not following %s anymore.' % username)
    return redirect(url_for('.user', username=username))


@main.route('/followers/<username>')
def followers(username):
    previous = request.args.get('previous','main.index')
    title="Followers of"
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('main.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followers.paginate(
        page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
        error_out=False)
    follows = [{'user': item.follower, 'timestamp': item.timestamp}
               for item in pagination.items]
    return render_template('followers.html', user=user, title=title, previous=previous,
                           endpoint='.followers', pagination=pagination,
                           follows=follows)


@main.route('/followed-by/<username>')
def followed_by(username):
    previous = request.args.get('previous','main.index')
    title="Followed by"
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('main.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followed.paginate(
        page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
        error_out=False)
    follows = [{'user': item.followed, 'timestamp': item.timestamp}
               for item in pagination.items]
    return render_template('followers.html', user=user, title=title, previous=previous,
                           endpoint='.followed_by', pagination=pagination,
                           follows=follows)

@main.route('/all')
@login_required
def show_all():
    resp = make_response(redirect(url_for('main.index')))
    resp.set_cookie('show_followed', '', max_age=30*24*60*60)
    return resp


@main.route('/followed')
@login_required
def show_followed():
    resp = make_response(redirect(url_for('main.index')))
    resp.set_cookie('show_followed', '1', max_age=30*24*60*60)
    return resp

@main.route('/moderate')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate():
    previous = request.args.get('previous','main.index')
    page = request.args.get('page', 1, type=int)
    pagination = Comment.query.order_by(Comment.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
        error_out=False)
    comments = pagination.items
    return render_template('moderate.html', comments=comments, previous=previous,
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

@main.route('/ckeditor')
@login_required
@admin_required
def ckeditor():
    previous = request.args.get('previous','main.index')
    form = RichTextForm()
    title = "CKEDITOR"
    return render_template('only_form.html',form = form, title=title, previous=previous)
    
@main.route('/about')
def about():
    previous = request.args.get('previous','main.index')
    title = "About"
    user = User.query.get(1)
    page = request.args.get('page', 1, type=int)
    config = Setting.query.filter_by(name='ABOUT_IDENTIFY').first()
    pagination = Post.query.filter(Post.author.has(role_id=3),
                        Post.body_html.like(f"%{config.value}%")
                 ).order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    return render_template('about.html', user=user, posts=posts, title=title, previous=previous,
                                         pagination=pagination)
    
@main.route('/uploads', methods = ['POST', 'GET'])
@login_required
def uploads():
    previous = request.args.get('previous','main.index')
    form = UploadForm()
    if form.validate_on_submit():
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename =  secure_filename(file.filename)
            data = file.read()
            document = Document(name=filename,
                                data = data,
                                post = False,
                                author_data = current_user._get_current_object())
            db.session.add(document)
            db.session.commit()
            flash(f'{filename} upload success.')
            return redirect(url_for('main.uploads'))
            
    page = request.args.get('page', 1, type=int)
    pagination = Document.query.order_by(Document.name.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    files = pagination.items
    
    page_head = "Uploaded files"
    return render_template('uploads.html', form=form, files=files, previous=previous,
                                         pagination=pagination)
    
def allowed_file(filename):
    config = Setting.query.filter_by(name='ALLOWED_EXTENSIONS').first().name.split("|")
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in config

def get_list_files(filter_file):
    filter_file = f"%{filter_file}%"
    files = Document.query.filter(Document.name.like(filter_file)).all()
    return files

@main.route('/ckeditor_uploads', methods = ['POST'])
@login_required
def ckeditor_uploads():
    file = request.files.get('upload')
    if allowed_file(file.filename):
        filename =  secure_filename(file.filename)
        filename_exist = Document.query.filter_by(name=filename).filter_by(author_id=current_user.id).first()
        if filename_exist != None:
            return upload_fail(message='You have uploaded a file with such a name before. Please check it in "My Files"')
        data = file.read()
        document = Document(name=filename,
                            data = data,
                            post = True,
                            author_data = current_user._get_current_object())
        db.session.add(document)
        db.session.commit()
        url = url_for('main.view', filename=filename)
        return upload_success(url, filename=filename)
    else:
        return upload_fail(message='File\'s type is not allow to upload!')


@main.route('/view/<path:filename>', methods=['GET', 'POST'])
def view(filename):
    returned_file = Document.query.filter_by(name=filename).first_or_404()
    return send_file(io.BytesIO(returned_file.data), attachment_filename=returned_file.name)

@main.route('/download/<path:filename>', methods=['GET', 'POST'])
def download(filename):
    returned_file = Document.query.filter_by(name=filename).first_or_404()
    return send_file(io.BytesIO(returned_file.data), attachment_filename=returned_file.name, as_attachment=True)

@main.route('/download', methods=['POST', 'GET'])
def download_file():
    previous = request.args.get('previous','main.index')
    form = SearchForm()
    page = request.args.get('page', 1, type=int)
    pagination = Document.query.order_by(Document.name.desc()).paginate(
                       page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
                       error_out=False)
    files = pagination.items
    if form.validate_on_submit():
        filter_file  = form.search.data
        files = get_list_files(filter_file)
    return render_template('download.html', form=form, files=files, previous=previous,
                                     pagination=pagination)

@main.route('/myfiles', methods=['POST', 'GET'])
@login_required
def myfiles():
    previous = request.args.get('previous','main.index')
    form = SearchForm()
    page = request.args.get('page', 1, type=int)
    pagination = Document.query.filter_by(author_id=current_user.id).paginate(
                       page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
                       error_out=False)
    if form.validate_on_submit():
        filter_file  = form.search.data
        filter_file  = f"%{filter_file}%" 
        pagination = Document.query.filter_by(author_id=current_user.id).filter(Document.name.like(filter_file)).paginate(
                       page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
                       error_out=False)
    files = pagination.items
    return render_template('myfiles.html', form=form, files=files, previous=previous,
                                     pagination=pagination)

@main.route('/download/delete/<path:filename>', methods=['GET', 'POST'])
@login_required
@admin_required
def delete_file(filename):
    returned_file = Document.query.filter_by(name=filename).first_or_404()
    returned_file.delete()
    flash('Deleted file')
    return redirect(url_for('main.download_file'))

@main.route('/like/<post_id>', methods = ['POST'])
@login_required
def like(post_id):
    post = Post.query.filter_by(id=post_id).first()
    if not post is None:
        current_user.like(post)
        return jsonify(liked_count=post.liked_post.count())
    return redirect(url_for('main.index'))

@main.route('/rank')
def rank():
    previous = request.args.get('previous','main.index')
    page = request.args.get('page', 1, type=int)
    posts = Post.query.filter(Post.author.has(role_id=1) | Post.author.has(role_id=2)).all()
    posts.sort(reverse=True, key=condition)
    user = posts[:49]
    return render_template('rank.html', requests=user, page=page, previous=previous)
def condition(post):
    return str(post.liked_post.count()) + str(post.timestamp)

@main.route('/speak_topic', methods=['GET', 'POST'])
def speak_topic():
    previous = request.args.get('previous','main.index')
    title = "Weekly Speak Topic"
    page = request.args.get('page', 1, type=int)
    config = Setting.query.filter_by(name="SPEAK_TOPIC_IDENTIFY").first()
    pagination = Post.query.filter(Post.author.has(role_id=3),
                        Post.body_html.like(f"%{config.value}%")
                 ).order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    return render_template('list_post.html', posts=posts, title=title, previous=previous,
                                      pagination=pagination)

@main.route('/speak_topic/<int:id>', methods=['GET', 'POST'])
def topic_post(id):
    previous = request.args.get('previous','main.index')
    post = Post.query.get_or_404(id)
    config = Setting.query.filter_by(name="SPEAK_TOPIC_IDENTIFY").first()
    if (not post.author.is_administrator()) or (config.value not in post.body_html):
        abort(403)
    page = request.args.get('page', 1, type=int)
    hashtag = find_hashtag(post.body_html)
    pagination = Post.query.filter(Post.body_html.like(f"%#{hashtag}%") &
                                 (Post.author.has(role_id=1) | 
                                 Post.author.has(role_id=2)) ).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    return render_template('topic_post.html', post=post, posts=posts, previous=previous,
                                      pagination=pagination)
def find_hashtag(text):
    config = Setting.query.filter_by(name="SPEAK_TOPIC_IDENTIFY").first()
    lists = text.split(config.value)
    return lists[1].split(" ")[0]

@main.route('/user_manual', methods=['GET', 'POST'])
def user_manual():
    previous = request.args.get('previous','main.index')
    title = "User Manual"
    page = request.args.get('page', 1, type=int)
    config = Setting.query.filter_by(name="USER_MANUAL_IDENTIFY").first()
    pagination = Post.query.filter(Post.author.has(role_id=3),
                        Post.body_html.like(f"%{config.value}%")
                 ).order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    expand_all_post = True
    return render_template('list_post.html', posts=posts, title=title, previous=previous,
                                     expand_all_post=expand_all_post, pagination=pagination)

@main.route('/admin_manual', methods=['GET', 'POST'])
def admin_manual():
    previous = request.args.get('previous','main.index')
    title = "Administrator Manual"
    page = request.args.get('page', 1, type=int)
    config = Setting.query.filter_by(name="ADMIN_MANUAL_IDENTIFY").first()
    pagination = Post.query.filter(Post.author.has(role_id=3),
                        Post.body_html.like(f"%{config.value}%")
                 ).order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    expand_all_post = True
    return render_template('list_post.html', posts=posts, title=title, previous=previous,
                                     expand_all_post=expand_all_post, pagination=pagination)
