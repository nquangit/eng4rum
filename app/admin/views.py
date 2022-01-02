from flask import render_template, redirect, url_for, abort, flash, request, \
    current_app, make_response, send_from_directory, send_file, jsonify
from werkzeug import secure_filename
from flask_login import login_required, current_user
from ..lib.flask_ckeditor import upload_fail, upload_success
from . import admin
from .forms import MultipleUploadForm, SelectForm, TypeForm, AddConfigurationForm
from .. import db
from ..models import Permission, Role, User, Post, Comment, Like, Document, Setting
from ..decorators import admin_required, permission_required

@admin.route('/config')
@login_required
@admin_required
def configuration():
    previous = request.args.get('previous','main.index')
    title = "Configuration"
    configurations = Setting.query.order_by(Setting.name.asc()).all()
    return render_template('admin/configuration.html', title=title,  previous=previous,
                                         configurations=configurations)

@admin.route('/config/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_config():
    previous = request.args.get('previous','main.index')
    title = "Add Configuration"
    form = AddConfigurationForm()
    if form.validate_on_submit():
        if '|' not in form.data.data:
            data = " "
        else:
            data = form.data.data
        config = Setting(name = form.name.data.replace(' ','_').upper(),
                         value = form.value.data,
                         data = data)
        db.session.add(config)
        flash('Add configuration complete')
        return redirect(url_for('admin.configuration'))
        
    return render_template('admin/only_form.html', title=title, form=form, previous=previous)

@admin.route('/config/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_config(id):
    previous = request.args.get('previous','main.index')
    setting = Setting.query.get_or_404(id)
    if setting.data != " ":
        form = SelectForm(setting=setting)
        lists = setting.data.split('|')
    else:
        form = TypeForm(setting=setting)
    if form.validate_on_submit():
        if setting.data != " ":
            tmp = form.Select.data
            setting.value = lists[form.Select.data]
        else:
            setting.value = form.Value.data
        db.session.add(setting)
        flash("Edit Complete")
        return redirect(url_for('admin.configuration'))
    if setting.data != " ":
        form.Select.data = lists.index(setting.value)
    else:
        form.Value.data = setting.value
    title = f"Edit Configuration: {setting.name}"
    return render_template('admin/only_form.html', title=title,  previous=previous,
                                        form=form)

@admin.route('/config/<int:id>/delete', methods=['GET', 'POST'])
@login_required
@admin_required
def del_config(id):
    config = Setting.query.get_or_404(id)
    config.delete()
    return redirect(url_for('admin.configuration'))

@admin.route('/confirm')
@login_required
@admin_required
def confirm():
    previous = request.args.get('previous','main.index')
    page = request.args.get('page', 1, type=int)
    #tmp = User.query.order_by(User.confirmed.asc())
    pagination = User.query.order_by(User.confirmed.asc()).order_by(User.member_since.desc()).paginate(
                     page, per_page=current_app.config['FLASKY_REQUEST_PER_PAGE'],
                     error_out=False)
    requests = pagination.items
    return render_template('admin/confirm.html', requests=requests, previous=previous,
                            pagination=pagination, page=page)

@admin.route('/confirm/enable/<int:id>')
@login_required
@admin_required
#@login.user_loader
def confirm_enable(id):
    conf = User.query.get_or_404(id)
    conf.confirm_acc()
    return redirect(url_for('admin.confirm', page=request.args.get('page', 1, type=int)))


@admin.route('/confirm/disable/<int:id>')
@login_required
@admin_required
def confirm_disable(id):
    conf = User.query.get_or_404(id)
    conf.confirm_acc()
    return redirect(url_for('admin.confirm', page=request.args.get('page', 1, type=int)))


@admin.route('/confirm/delete/<int:id>')
@login_required
@admin_required
def delete(id):
    conf = User.query.get_or_404(id)
    conf.delete()
    return redirect(url_for('admin.confirm', page=request.args.get('page', 1, type=int)))
    
@admin.route('/confirm/set_moderate/<int:id>')
@login_required
@admin_required
def set_moderate(id):
    conf = User.query.get_or_404(id)
    conf.set_moderate()
    return redirect(url_for('admin.confirm', page=request.args.get('page', 1, type=int)))
    
def allowed_file(filename):
    config = Setting.query.filter_by(name='ALLOWED_EXTENSIONS').first().name.split("|")
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in config

@admin.route('/multiple_uploads', methods = ['POST', 'GET'])
@login_required
@admin_required
def multiple_uploads():
    previous = request.args.get('previous','main.index')
    form = MultipleUploadForm()
    if form.validate_on_submit():
        complete = 0
        error = 0
        if 'file' not in request.files:
            flash('This field is required.')
            return redirect(url_for('admin.multiple_uploads'))
        for file in request.files.getlist('file'):
            if file:
                filename =  secure_filename(file.filename)
                data = file.read()
                document = Document(name=filename,
                                    data = data,
                                    post = False,
                                    author_data = current_user._get_current_object())
                db.session.add(document)
                db.session.commit()
                flash(f'{filename} upload success.')
                complete += 1
            else:
                flash(f'No file: {file.filename}')
                error += 1
                return redirect(url_for('admin.multiple_uploads'))
        flash(f'Upload success. [Total]: {complete+error}, [Complete]: {complete}, [Error]: {error}')
        return redirect(url_for('admin.multiple_uploads'))
    
    page = request.args.get('page', 1, type=int)
    pagination = Document.query.order_by(Document.name.desc()).paginate(
                                                 page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
                                                 error_out=False)
    files = pagination.items
    
    return render_template('admin/uploads.html', form=form, files=files, previous=previous,
                                               pagination=pagination) 

def get_list_files(filter_file):
    filter_file = f"%{filter_file}%"
    files = Document.query.filter(Document.name.like(filter_file)).all()
    return files
