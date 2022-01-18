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
    CommentForm, UploadForm, SearchForm, TypeForm
from .. import db, csrfprotect
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
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


@main.route('/', methods=['GET', 'POST'])
@main.route('/index', methods=['GET', 'POST'])
def index():
    previous = request.args.get('previous', '/index')
    if current_user.is_administrator():
        current_app.config['CKEDITOR_PKG_TYPE'] = Setting.query.filter_by(
            name='CKEDITOR_PKG_TYPE_ADMIN').first().value
    else:
        current_app.config['CKEDITOR_PKG_TYPE'] = Setting.query.filter_by(
            name='CKEDITOR_PKG_TYPE_USER').first().value
    page = request.args.get('page', 1, type=int)
    index_show = request.cookies.get('index_show', '')
    if index_show == 'show_followed':
        if current_user.is_authenticated:
            query = current_user.followed_posts
        else:
            abort(403)
    elif index_show == 'weekly_speak_post':
        config = Setting.query.filter_by(name="SPEAK_TOPIC_IDENTIFY").first()
        if config == None:
            abort(500)
        filters_list = [(e.id) for e in Role.query.all() if (
            e.permissions & Permission.WRITE_WEEKLY_SPEAK_TOPIC == Permission.WRITE_WEEKLY_SPEAK_TOPIC)]
        filters_list_hashtag = [find_hashtag(e.body_html) for e in Post.query.join(User).join(
            Role).filter((Post.body_html.like(f"%{config.value}%"))).filter(Role.id.in_(filters_list)).all()]
        filters_list_post = [
            (e.id) for f in filters_list_hashtag for e in Post.query.all() if f in e.body_html]
        filters_list_user = [(e.id) for e in Role.query.all() if not (
            e.permissions & Permission.WRITE_WEEKLY_SPEAK_TOPIC == Permission.WRITE_WEEKLY_SPEAK_TOPIC)]
        query = Post.query.join(User).join(Role).filter(
            Post.id.in_(filters_list_post) & Role.id.in_(filters_list_user))
    elif index_show == 'admin_post':
        filters_list = [(e.id) for e in Role.query.all() if (
            e.permissions & Permission.ADMINISTER == Permission.ADMINISTER)]
        query = Post.query.join(User).join(
            Role).filter(Role.id.in_(filters_list))
    elif index_show == 'teacher_post':
        filters_list = [(e.id) for e in Role.query.all() if ((e.permissions & Permission.TEACHER ==
                                                              Permission.TEACHER) and (e.permissions & Permission.ADMINISTER != Permission.ADMINISTER))]
        query = Post.query.join(User).join(
            Role).filter(Role.id.in_(filters_list))
    else:
        index_show = ""
        config = Setting.query.filter_by(name="SPEAK_TOPIC_IDENTIFY").first()
        if config == None:
            abort(500)
        filters_list = [(e.id) for e in Role.query.all() if (
            e.permissions & Permission.WRITE_WEEKLY_SPEAK_TOPIC == Permission.WRITE_WEEKLY_SPEAK_TOPIC)]
        filters_list_hashtag = [find_hashtag(e.body_html) for e in Post.query.join(User).join(
            Role).filter((Post.body_html.like(f"%{config.value}%"))).filter(Role.id.in_(filters_list)).all()]
        if len(filters_list_hashtag) == 0:
            query = Post.query
        else:
            filters_list_post = []
            for e in Post.query.all():
                add = False
                for hashtag in filters_list_hashtag:
                    if (f'#{hashtag}' in e.body_html):
                        if (e.author.role.permissions & Permission.WRITE_WEEKLY_SPEAK_TOPIC != Permission.WRITE_WEEKLY_SPEAK_TOPIC):
                            add = False
                            break
                        else:
                            filters_list_post.append(e.id)
                            break
                    else:
                        add = True
                if add:
                    filters_list_post.append(e.id)
            query = Post.query.filter(Post.id.in_(filters_list_post))
    pagination = query.order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    cmt = [i.comments.order_by(Comment.timestamp.desc()).limit(3).all() for i in posts]
    slide_in_text = Setting.query.filter_by(name="SLIDE_IN_TEXT").first()
    if slide_in_text == None:
        setting = Setting(name = 'SLIDE_IN_TEXT',
                          value = 'Welcome to Eng4rum',
                          data = ' ')
        db.session.add(setting)
        return redirect(url_for('main.index'))
    slide_in_text = slide_in_text.value
    return render_template('index.html', posts=posts, previous=previous, slide_in_text=slide_in_text, cmt=cmt,
                           index_show=index_show, pagination=pagination)


@main.route('/write_article', methods=['GET', 'POST'])
@login_required
def write_article():
    title = "Write Article"
    previous = request.args.get('previous', '/index')
    form = PostForm()
    if current_user.is_administrator():
        current_app.config['CKEDITOR_PKG_TYPE'] = Setting.query.filter_by(
            name='CKEDITOR_PKG_TYPE_ADMIN').first().value
    else:
        current_app.config['CKEDITOR_PKG_TYPE'] = Setting.query.filter_by(
            name='CKEDITOR_PKG_TYPE_USER').first().value
    if current_user.can(Permission.WRITE_ARTICLES) and \
            form.validate_on_submit():
        post = Post(body=form.body.data,
                    author=current_user._get_current_object())
        db.session.add(post)
        return redirect(url_for('main.index'))
    return render_template('edit_post.html', form=form, previous=previous, title=title)


@main.route('/user/<username>')
def user(username):
    previous = request.args.get('previous', '/index')
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
        posts = pagination.items
    elif show == 'files':
        pagination = Document.query.filter_by(author_id=user.id).order_by(Document.name.desc()).paginate(
            page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
            error_out=False)
        posts = pagination.items
    else:
        show = ''
        pagination = user.posts.order_by(Post.timestamp.desc()).paginate(
            page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
            error_out=False)
        posts = pagination.items
        cmt = [i.comments.order_by(Comment.timestamp.desc()).limit(3).all() for i in posts]
    return render_template('user.html', user=user, posts=posts, pagination=pagination,
                           previous=previous, show=show, cmt=cmt)


@main.route('/user/<username>/all')
@login_required
def user_show_all(username):
    resp = make_response(
        redirect(url_for('.user', username=username) + "#all"))
    resp.set_cookie('show', '', max_age=30*24*60*60)
    return resp


@main.route('/user/<username>/files')
@login_required
def user_show_files(username):
    resp = make_response(
        redirect(url_for('.user', username=username) + '#files'))
    resp.set_cookie('show', 'files', max_age=30*24*60*60)
    return resp


@main.route('/user/<username>/image_gallery')
@login_required
def image_gallery(username):
    resp = make_response(
        redirect(url_for('.user', username=username) + '#image_gallery'))
    resp.set_cookie('show', 'image', max_age=30*24*60*60)
    return resp


@main.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    previous = request.args.get('previous', '/index')
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
    previous = request.args.get('previous', '/index')
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
    previous = request.args.get('previous', '/index')
    post = Post.query.get_or_404(id)
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            abort(403)
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
    pagination = post.comments.order_by(Comment.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
        error_out=False)
    comments = pagination.items
    return render_template('post.html', post=post, form=form, previous=previous,
                           comments=comments, pagination=pagination)


@main.route('/post/comment', methods=['POST'])
@login_required
def comment():
    post_id = request.json['post_id']
    comment_body = request.json['comment_body']
    post = Post.query.get(post_id)
    if post_id == None:
        return "Not Found", 404
    comment = Comment(body=comment_body,
                          post=post,
                          author=current_user._get_current_object())
    db.session.add(comment)
    db.session.flush()
    db.session.refresh(comment)
    cmt = jsonify(timestamp=comment.timestamp)
    return cmt, 200

@main.route('/post/delete', methods=['POST'])
@login_required
def delete_post():
    id = request.json['post_id']
    post = Post.query.get(id)
    if post == None:
        print('not found')
        return "Not Found", 404
    if post.author_id != current_user.id and not current_user.is_administrator():
        print('Abort')
        return "Abort", 403
    post.delete()
    return "Deleted post", 200


@main.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    title = "Edit Post"
    previous = request.args.get('previous', '/index')
    post = Post.query.get_or_404(id)
    if current_user != post.author and \
            not current_user.can(Permission.ADMINISTER):
        abort(403)
    if current_user.is_administrator():
        current_app.config['CKEDITOR_PKG_TYPE'] = Setting.query.filter_by(
            name='CKEDITOR_PKG_TYPE_ADMIN').first().value
    else:
        current_app.config['CKEDITOR_PKG_TYPE'] = Setting.query.filter_by(
            name='CKEDITOR_PKG_TYPE_USER').first().value
    form = PostForm()
    if form.validate_on_submit():
        post.body = form.body.data
        db.session.add(post)
        flash('The post has been updated.')
        return redirect(url_for('.post', id=post.id))
    form.body.data = post.body
    return render_template('edit_post.html', form=form,  previous=previous, title=title)


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
    previous = request.args.get('previous', '/index')
    title = "Followers of"
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
    previous = request.args.get('previous', '/index')
    title = "Followed by"
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
def show_all():
    resp = make_response(redirect(url_for('main.index')))
    resp.set_cookie('index_show', '', max_age=24*60*60)
    return resp


@main.route('/followed')
@login_required
def show_followed():
    resp = make_response(redirect(url_for('main.index')))
    resp.set_cookie('index_show', 'show_followed', max_age=24*60*60)
    return resp


@main.route('/weekly_speak_post')
def weekly_speak_post():
    resp = make_response(redirect(url_for('main.index')))
    resp.set_cookie('index_show', 'weekly_speak_post', max_age=24*60*60)
    return resp


@main.route('/admin_post')
def admin_post():
    resp = make_response(redirect(url_for('main.index')))
    resp.set_cookie('index_show', 'admin_post', max_age=24*60*60)
    return resp


@main.route('/teacher_post')
def teacher_post():
    resp = make_response(redirect(url_for('main.index')))
    resp.set_cookie('index_show', 'teacher_post', max_age=24*60*60)
    return resp


@main.route('/moderate')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate():
    previous = request.args.get('previous', '/index')
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
    if comment.author.is_administrator():
        abort(403)
    comment.disabled = True
    db.session.add(comment)
    return redirect(url_for('.moderate',
                            page=request.args.get('page', 1, type=int)))


@main.route('/moderate/delete/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def delete_cmt(id):
    comment = Comment.query.get_or_404(id)
    if comment.author.is_administrator() and not current_user.is_administrator():
        abort(403)
    comment.delete()
    return redirect(url_for('.moderate',
                            page=request.args.get('page', 1, type=int)))


@main.route('/ckeditor')
@login_required
@admin_required
def ckeditor():
    previous = request.args.get('previous', '/index')
    form = RichTextForm()
    title = "CKEDITOR"
    return render_template('only_form.html', form=form, title=title, previous=previous)


@main.route('/about')
def about():
    previous = request.args.get('previous', '/index')
    title = "About"
    user = User.query.get(1)
    page = request.args.get('page', 1, type=int)
    config = Setting.query.filter_by(name='ABOUT_IDENTIFY').first()
    if config == None:
        setting = Setting(name = 'ABOUT_IDENTIFY',
                          value = '[About]',
                          data = ' ')
        db.session.add(setting)
        db.session.commit()
        return redirect(url_for('main.about'))
    filters_list = [(e.id) for e in Role.query.all() if (
        e.permissions & Permission.ADMINISTER == Permission.ADMINISTER)]
    pagination = Post.query.filter(Role.id.in_(filters_list),
                                   Post.body_html.like(f"%{config.value}%")
                                   ).order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    return render_template('about.html', user=user, posts=posts, title=title, previous=previous,
                           pagination=pagination)


@main.route('/uploads', methods=['POST', 'GET'])
@login_required
def uploads():
    previous = request.args.get('previous', '/index')
    form = UploadForm(prefix='upload_file')
    searchform = SearchForm(prefix='search_file')
    page = request.args.get('page', 1, type=int)
    pagination = Document.query.filter_by(author_id=current_user.id).order_by(Document.name.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    if form.validate_on_submit() and form.submit.data:
        file = request.files['file']
        if not file :
            flash('Data required !!!')
            return redirect(url_for('main.uploads'))
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            data = file.read()
            document = Document(name=filename,
                                data=data,
                                post=False,
                                author_data=current_user._get_current_object())
            db.session.add(document)
            db.session.commit()
            flash(f'{filename} upload success.')
            return redirect(url_for('main.uploads'))
        else:
            flash(f'{filename} not allow to upload.')
            return redirect(url_for('main.uploads'))
    if searchform.validate_on_submit() and searchform.submit.data:
        print('oke')
        filter_file = searchform.search.data
        filter_file = f"%{filter_file}%"
        pagination = Document.query.filter_by(author_id=current_user.id).filter(Document.name.like(filter_file)).paginate(
                     page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
                     error_out=False)
    files = pagination.items
    page_head = "Uploaded files"
    return render_template('uploads.html', form=form, files=files, previous=previous,
                           searchform=searchform, pagination=pagination)


def allowed_file(filename):
    config = Setting.query.filter_by(
        name='ALLOWED_EXTENSIONS').first().value.split("|")
    if config == None:
        abort(500)
    return '.' in filename and \
           filename.rsplit('.', 1)[-1] in config


def get_list_files(filter_file):
    filter_file = f"%{filter_file}%"
    config = Setting.query.filter_by(name='NOT_SHOW_FILE').first().value
    if config == None:
        abort(500)
    config = f"%{config}%"
    files = Document.query.filter(Document.name.like(
        filter_file) & Document.name.notlike(config)).all()
    return files


@main.route('/ckeditor_uploads', methods=['POST'])
@login_required
@csrfprotect.exempt
def ckeditor_uploads():
    file = request.files.get('upload')
    if allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filename_exist = Document.query.filter_by(
            name=filename).filter_by(author_id=current_user.id).first()
        if filename_exist != None:
            return upload_fail(message='You have uploaded a file with such a name before. Please check it in "My Files"')
        data = file.read()
        document = Document(name=filename,
                            data=data,
                            post=True,
                            author_data=current_user._get_current_object())
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


@main.route('/download/all')
def show_all_file():
    resp = make_response(redirect(url_for('main.download_file')))
    resp.set_cookie('file_show', '', max_age=24*60*60)
    return resp


@main.route('/download/documents')
def show_documents():
    resp = make_response(redirect(url_for('main.download_file')))
    resp.set_cookie('file_show', 'documents', max_age=24*60*60)
    return resp


@main.route('/download/exercises')
def show_exercises():
    resp = make_response(redirect(url_for('main.download_file')))
    resp.set_cookie('file_show', 'exercises', max_age=24*60*60)
    return resp


@main.route('/download/in_post')
def show_in_post():
    resp = make_response(redirect(url_for('main.download_file')))
    resp.set_cookie('file_show', 'in_post', max_age=24*60*60)
    return resp


@main.route('/download', methods=['POST', 'GET'])
def download_file():
    previous = request.args.get('previous', '/index')
    searchform = SearchForm()
    page = request.args.get('page', 1, type=int)
    file_show = request.cookies.get('file_show', '')
    query = download_view(file_show)
    if searchform.validate_on_submit():
        filter_file = searchform.search.data
        file_show = request.cookies.get('file_show', '')
        query = download_view(file_show)
        query = query.filter(Document.name.like(f"%{filter_file}%"))
    pagination = query.order_by(Document.name.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    files = pagination.items
    return render_template('download.html', searchform=searchform, files=files, previous=previous,
                           file_show=file_show, pagination=pagination)


def download_view(file_show):
    not_show = Setting.query.filter_by(name='NOT_SHOW_FILE').first().value
    not_show = f"%{not_show}%"
    exercises_id = Setting.query.filter_by(name='EXERCISES_IDENTIFY').first()
    if exercises_id == None:
        setting = Setting(name='EXERCISES_IDENTIFY')
        setting.value = "EXERCISES"
        setting.data = ' '
        db.session.add(setting)
        db.session.commit()
        return redirect(url_for('main.download_file'))
    if file_show == 'documents':
        query = Document.query.filter((Document.name.notlike(not_show)) & 
                                      (Document.name.notlike(f"%{exercises_id.value}%")) & 
                                      (Document.post == False))
    elif file_show == 'exercises':
        query = Document.query.filter((Document.name.notlike(not_show)) & 
                                      (Document.name.like(f"%{exercises_id.value}%")) & 
                                      (Document.post == False))
    elif file_show == 'in_post':
        query = Document.query.filter((Document.name.notlike(not_show)) & 
                                      (Document.post == True))
    else:
        file_show = ''
        query = Document.query.filter(Document.name.notlike(not_show))
    return query


@main.route('/uploads/rename_file/<filename>', methods=['POST', 'GET'])
@login_required
def rename_file(filename):
    previous = request.args.get('previous', '/index')
    form = TypeForm()
    file = Document.query.filter_by(name=filename).first_or_404()
    if file.author_id != current_user.id and not current_user.is_teacher():
        abort(403)
    if file.author_data.is_administrator() and not current_user.is_administrator():
        abort(403)
    extension = file.name.split('.')[-1]
    filename = ''.join(file.name.split('.')[0:-1])
    if form.validate_on_submit():
        posts = Post.query.filter(Post.body_html.like(
            f"%{filename}.{extension}%")).filter_by(author_id=file.author_id)
        new_filename = secure_filename(form.value.data)
        file.name = f"{new_filename}.{extension}"
        for post in posts:
            post.body_html = post.body_html.replace(
                f"{filename}.{extension}", f"{new_filename}.{extension}")
            db.session.add(post)
        db.session.add(file)
        flash(f'Complete change filename to {new_filename}.{extension}')
        return redirect(url_for('main.uploads'))
    form.value.data = ''.join(file.name.split('.')[0:-1])
    return render_template('only_form.html', form=form, title="Rename File")


@main.route('/download/delete/<path:filename>', methods=['POST'])
@login_required
def delete_file(filename):
    returned_file = Document.query.filter_by(name=filename).first()
    if returned_file == None:
        return "Not Found", 404
    if returned_file.id != current_user.id and not current_user.is_administrator():
        return "Abort", 403
    returned_file.delete()
    return "Deleted file", 200


@main.route('/like', methods=['POST'])
@login_required
def like():
    post_id = request.json['post_id']
    post = Post.query.filter_by(id=post_id).first()
    if not post is None:
        if not current_user.is_liked(post):
            like = True
        else:
            like = False
        current_user.like(post)
        return jsonify(liked_count=post.liked_post.count(), like=like), 200
    else:
        return "Not Found", 404


@main.route('/rank')
def rank():
    previous = request.args.get('previous', '/index')
    page = request.args.get('page', 1, type=int)
    filters_list = [(e.id) for e in Role.query.all() if not (
        e.permissions & Permission.TEACHER == Permission.TEACHER)]
    posts = Post.query.join(User).join(Role).filter(
        Role.id.in_(filters_list)).all()
    posts.sort(reverse=True, key=condition)
    user = posts[:49]
    return render_template('rank.html', requests=user, page=page, previous=previous)


def condition(post):
    return str(post.liked_post.count()) + str(post.timestamp)


@main.route('/speak_topic', methods=['GET', 'POST'])
def speak_topic():
    previous = request.args.get('previous', '/index')
    title = "Weekly Topic"
    page = request.args.get('page', 1, type=int)
    config = Setting.query.filter_by(name="SPEAK_TOPIC_IDENTIFY").first()
    if config == None:
        abort(500)
    filters_list = [(e.id) for e in Role.query.all() if (
        e.permissions & Permission.WRITE_WEEKLY_SPEAK_TOPIC == Permission.WRITE_WEEKLY_SPEAK_TOPIC)]
    pagination = Post.query.join(User).join(Role).filter((Post.body_html.like(f"%{config.value}%"))).filter(Role.id.in_(filters_list)
                                                                                                            ).order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    cmt = [i.comments.order_by(Comment.timestamp.desc()).limit(3).all() for i in posts]
    return render_template('list_post.html', posts=posts, title=title, previous=previous,
                           pagination=pagination, cmt=cmt)


@main.route('/speak_topic/<int:id>', methods=['GET', 'POST'])
def topic_post(id):
    previous = request.args.get('previous', '/index')
    post = Post.query.get_or_404(id)
    config = Setting.query.filter_by(name="SPEAK_TOPIC_IDENTIFY").first()
    if config == None:
        abort(500)
    if (not post.author.is_administrator()) or (config.value not in post.body_html):
        abort(403)
    page = request.args.get('page', 1, type=int)
    hashtag = find_hashtag(post.body_html)
    filters_list = [(e.id) for e in Role.query.all() if not (
        e.permissions & Permission.WRITE_WEEKLY_SPEAK_TOPIC == Permission.WRITE_WEEKLY_SPEAK_TOPIC)]
    pagination = Post.query.join(User).join(Role).filter(Post.body_html.like(f"%#{hashtag}%") &
                                                         Role.id.in_(filters_list)).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    return render_template('topic_post.html', post=post, posts=posts, previous=previous,
                           pagination=pagination)


def find_hashtag(text):
    config = Setting.query.filter_by(name="SPEAK_TOPIC_IDENTIFY").first()
    if config == None:
        abort(500)
    lists = text.split(config.value)
    #print(lists[1].split(" ")[0].split("<")[0])
    return lists[1].split(" ")[0].split("<")[0]


@main.route('/user_manual', methods=['GET', 'POST'])
def user_manual():
    previous = request.args.get('previous', '/index')
    title = "User Manual"
    page = request.args.get('page', 1, type=int)
    config = Setting.query.filter_by(name="USER_MANUAL_IDENTIFY").first()
    if config == None:
        abort(500)
    filters_list = [(e.id) for e in Role.query.all() if (
        e.permissions & Permission.ADMINISTER == Permission.ADMINISTER)]
    pagination = Post.query.join(User).join(Role).filter(Role.id.in_(filters_list),
                                                         Post.body_html.like(
                                                             f"%{config.value}%")
                                                         ).order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    expand_all_post = True
    return render_template('list_post.html', posts=posts, title=title, previous=previous,
                           expand_all_post=expand_all_post, pagination=pagination)


@main.route('/teacher_manual', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.TEACHER)
def teacher_manual():
    previous = request.args.get('previous', '/index')
    title = "Teacher Manual"
    page = request.args.get('page', 1, type=int)
    config = Setting.query.filter_by(name="TEACHER_MANUAL_IDENTIFY").first()
    if config == None:
        abort(500)
    filters_list = [(e.id) for e in Role.query.all() if (
        e.permissions & Permission.TEACHER == Permission.TEACHER)]
    pagination = Post.query.filter(Role.id.in_(filters_list),
                                   Post.body_html.like(f"%{config.value}%")
                                   ).order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    expand_all_post = True
    return render_template('list_post.html', posts=posts, title=title, previous=previous,
                           expand_all_post=expand_all_post, pagination=pagination)


@main.route('/our_team')
def our_team():
    return render_template('misc/team.html', title="Team")