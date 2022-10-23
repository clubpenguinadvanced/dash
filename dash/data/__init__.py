from flask import Flask
from flask_sqlalchemy import SQLAlchemy

USER = ''
PASSWORD = ''
HOST = '127.0.0.1:3306'
NAME = ''

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = (f'mysql://'
                			f'{USER}:'
               				f'{PASSWORD}@'
                  			f'{HOST}/'
             				f'{NAME}')
db = SQLAlchemy(app)

db.init_app(app)
