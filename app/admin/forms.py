from flask_wtf import FlaskForm
from wtforms import TextAreaField, SelectField, SubmitField, MultipleFileField, StringField
from wtforms.validators import Required, DataRequired, Length
from ..models import Setting


class SearchForm(FlaskForm):
    search = StringField("Search")
    submit = SubmitField('Search')


class TypeForm(FlaskForm):
    Value = TextAreaField(validators=[Required()])
    submit = SubmitField('Save')


class SelectForm(FlaskForm):
    Select = SelectField(coerce=int)
    submit = SubmitField('Save')

    def __init__(self, setting, *args, **kwargs):
        super().__init__(*args, **kwargs)
        settings = Setting.query.filter_by(
            name=setting.name).first().data.split('|')
        self.Select.choices = [(settings.index(setting), setting)
                               for setting in settings]


class MultipleUploadForm(FlaskForm):
    file = MultipleFileField('Files', validators=[DataRequired()])
    submit = SubmitField('Upload')

    def validate_image(form, field):
        if field.data:
            field.data = re.sub(r'[^a-z0-9_.-]', '_', field.data)


class AddConfigurationForm(FlaskForm):
    name = StringField('Name of configuration: ', validators=[
                       Required(), Length(1, 128)])
    value = TextAreaField('Value for configuration: ', validators=[Required()])
    data = TextAreaField(
        "List value (with | separator).[Note] If it isn't have list value, fill this text area with a backspace. \nExample: full|standard|basic")
    submit = SubmitField('Add')
