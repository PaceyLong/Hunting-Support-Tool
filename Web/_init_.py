from numpy import append
import requests
import json
from cloudTrail import *
from flask import Flask
from .views import views

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'hjshjhdjah kjshkjdhjs'

    app.register_blueprint(views, url_prefix='/')

    return app





# cloudTrail_events = get_events('ReadOnly','true')
# print(cloudTrail_events)
