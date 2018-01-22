# -*- coding: utf-8 -*-
from flask.ext.cache import Cache
# from flask.ext.celery import Celery
from flask.ext.mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_login import LoginManager
from flask_moment import Moment

__all__ = ['mail', 'db', 'cache', 'celery', 'ldap']


mail = Mail()
db = SQLAlchemy()
cache = Cache()
# celery = Celery()
bootstrap = Bootstrap()
moment = Moment()
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'