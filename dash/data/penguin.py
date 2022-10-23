from . import db

class Penguin(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.VARCHAR(12), nullable=False, unique=True)
    password = db.Column(db.VARCHAR(60), nullable=False)
    loginKey = db.Column(db.TEXT)
    email = db.Column(db.VARCHAR(50))
    rank = db.Column(db.Integer, server_default=db.text("0"))
    permaBan = db.Column(db.Boolean, server_default=db.text("false"))
    coins = db.Column(db.Integer, server_default=db.text("500"))
    head = db.Column(db.Integer)
    face = db.Column(db.Integer)
    neck = db.Column(db.Integer)
    body = db.Column(db.Integer)
    hand = db.Column(db.Integer)
    feet = db.Column(db.Integer)
    color = db.Column(db.Integer)
    photo = db.Column(db.Integer)
    flag = db.Column(db.Integer)
    username_approved = db.Column(db.Boolean, server_default=db.text("false"))
    username_rejected = db.Column(db.Boolean, server_default=db.text("false"))
    joinTime = db.Column(db.DateTime, nullable=False, server_default=db.text("current_timestamp()"))

class PasswordReset(db.Model):
    __tablename__ = 'passwordReset'

    id = db.Column(db.ForeignKey('users.id', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True,
                           nullable=False)
    resetCode = db.Column(db.VARCHAR(60), nullable=False)
