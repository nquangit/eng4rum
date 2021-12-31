from flask_wtf import FlaskForm
from wtforms import TextAreaField, SelectField, SubmitField,MultipleFileField
from wtforms.validators import Required, DataRequired
from ..models import Setting

class TypeForm(FlaskForm):
    Value = TextAreaField(validators=[Required()])
    submit = SubmitField('Save')
        
class SelectForm(FlaskForm):
    Select = SelectField(coerce=int)
    submit = SubmitField('Save')

    def __init__(self, setting, *args, **kwargs):
        super().__init__(*args, **kwargs)
        settings = Setting.query.filter_by(name=setting.name).first().data.split('|')
        self.Select.choices = [(settings.index(setting), setting)
                                   for setting in settings]

class MultipleUploadForm(FlaskForm):
    file         = MultipleFileField('Files', validators=[DataRequired()])
    submit       = SubmitField('Upload')

    def validate_image(form, field):
        if field.data:
            field.data = re.sub(r'[^a-z0-9_.-]', '_', field.data)
