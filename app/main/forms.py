from flask_ckeditor import CKEditorField
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, BooleanField, SelectField, SubmitField, FileField
from wtforms.validators import Required, Length, Email, Regexp, DataRequired
from wtforms import ValidationError
from flask_pagedown.fields import PageDownField
from ..models import Role, User

class NameForm(FlaskForm):
    name=StringField('What is your name?', vaidators=[Required()])
    submit = SubmitField('Submit')

class EditProfileForm(FlaskForm):
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Submit')

class EditProfileAdminForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
    username = StringField('Username', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    confirmed = BooleanField('Confirmed')
    role = SelectField('Role', coerce=int)
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Submit')

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name)
                             for role in Role.query.order_by(Role.name).all()]
        self.user = user

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first().email != self.user.email:
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first().username != self.user.username:
            raise ValidationError('Username already in use.')

class PostForm(FlaskForm):
    body = CKEditorField("What's on your mind?", validators=[Required()])
    submit = SubmitField('Submit')

class CommentForm(FlaskForm):
    body = StringField("Enter your comment", validators=[Required()])
    submit = SubmitField('Submit')



########################################################################################
#_____________________________________Developing_______________________________________#
class UploadForm(FlaskForm):
    image        = FileField(u'Image File')
    description  = TextAreaField(u'Image Description')

    def validate_image(self, field):
        if field.data:
            field.data = re.sub(r'[^a-z0-9_.-]', '_', field.data)

def upload(request):
    form = UploadForm(request.POST)
    if form.image.data:
        image_data = request.FILES[form.image.name].read()
        open(os.path.join(UPLOAD_PATH, form.image.data), 'w').write(image_data)
