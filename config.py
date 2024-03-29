import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get(
        'SECRET_KEY') or 'NWYzZTEzNjNmOTRkNDA2MTY5NDhkZmQ3ZjQ3OGUyYjRiODk2MmExYmVhZGM4YzhlMDc0ZmU3ZWRkNzA4OTI2MiAgLQo'
    SSL_DISABLE = False
    FLASKY_ADMIN = 'huynhngocq5@gmail.com'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = True
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    FLASKY_MAIL_SUBJECT_PREFIX = '[Eng4rum]'
    FLASKY_MAIL_SENDER = 'EngSocial Admin <flasky@demo.com>'
    FLASKY_ADMIN = os.environ.get('FLASKY_ADMIN')
    FLASKY_POSTS_PER_PAGE = 20
    FLASKY_FOLLOWERS_PER_PAGE = 50
    FLASKY_COMMENTS_PER_PAGE = 30
    FLASKY_REQUEST_PER_PAGE = 30
    FLASKY_SLOW_DB_QUERY_TIME = 0.5
    CKEDITOR_SERVE_LOCAL = True
    CKEDITOR_FILE_UPLOADER = 'main.ckeditor_uploads'
    CKEDITOR_EXTRA_PLUGINS = ['html5video',
                              'html5audio', 'image', 'uploadimage', 'autogrow']
    ######### My config #########
    #autoEmbed_widget = 'embed' # 'embedsemantic'
    autoGrow_maxHeight = 0
    autoGrow_bottomSpace = 100
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    CKEDITOR_HEIGHT = 250
    #ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'doc', 'docx', 'jpg', 'png', 'mp4', 'mp3', 'wav', 'pptx'])
    #CKEDITOR_PKG_TYPE = 'standard'
    # SPEAK_TOPIC_IDENTIFY = 'hashtag: #'
    #USER_MANUAL_IDENTIFY = '[User Manual]'
    #ADMIN_MANUAL_IDENTIFY = '[Admin Manual]'
    #ABOUT_IDENTIFY = '[About]'
    ########### END #############

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data-dev.sqlite')


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data-test.sqlite')
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = "postgres://eng4rum_database_ngocquangitanony_user:EOhqFfzU1ctKniC6mPGehuanVHm3BdX6@dpg-c7j95mc41lsb9frvfu7g/eng4rum_database_ngocquangitanony"
        #os.environ.get('DATABASE_URL') or \
        #'sqlite:///' + os.path.join(basedir, 'data.sqlite')

    @classmethod
    def init_app(cls, app):
        Config.init_app(app)

        # email errors to the administrators
        #import logging
        #from logging.handlers import SMTPHandler
        #credentials = None
        #secure = None
        # if getattr(cls, 'MAIL_USERNAME', None) is not None:
        #    credentials = (cls.MAIL_USERNAME, cls.MAIL_PASSWORD)
        #    if getattr(cls, 'MAIL_USE_TLS', None):
        #        secure = ()
        # mail_handler = SMTPHandler(
        #    mailhost=(cls.MAIL_SERVER, cls.MAIL_PORT),
        #    fromaddr=cls.FLASKY_MAIL_SENDER,
        #    toaddrs=[cls.FLASKY_ADMIN],
        #    subject=cls.FLASKY_MAIL_SUBJECT_PREFIX + ' Application Error',
        #    credentials=credentials,
        #    secure=secure)
        # mail_handler.setLevel(logging.ERROR)
        # app.logger.addHandler(mail_handler)


class HerokuConfig(ProductionConfig):
    SSL_DISABLE = bool(os.environ.get('SSL_DISABLE'))

    @classmethod
    def init_app(cls, app):
        ProductionConfig.init_app(app)

        # handle proxy server headers
        from werkzeug.contrib.fixers import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app)

        # log to stderr
        import logging
        from logging import StreamHandler
        file_handler = StreamHandler()
        file_handler.setLevel(logging.WARNING)
        app.logger.addHandler(file_handler)


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'heroku': HerokuConfig,

    'default': DevelopmentConfig
}
