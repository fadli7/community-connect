'''
    facebook
    --------

    A simple Flask demo app that shows how to login with Facebook via rauth.

    Please note: you must do `from facebook import db; db.create_all()` from
    the interpreter before running this example!
    
    Due to Facebook's stringent domain validation, requests using this app 
    must originate from 127.0.0.1:5000.
'''

from flask import Flask, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy

from rauth.service import OAuth2Service

import json
import dateutil.parser as dateparser
import datetime
import jwt
from functools import wraps

# Flask config
SQLALCHEMY_DATABASE_URI = 'sqlite:///facebook.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False
SECRET_KEY = 'secret_key'
DEBUG = True
FB_CLIENT_ID = 'FB_CLIENT_ID'
FB_CLIENT_SECRET = 'FB_CLIENT_SECRET'
AUTH_TOKEN_EXPIRY_DAYS = 1
AUTH_TOKEN_EXPIRY_SECONDS = 20

# Flask setup
app = Flask(__name__, static_folder='static')
app.config.from_object(__name__)
db = SQLAlchemy(app)

# rauth OAuth 2.0 service wrapper
graph_url = 'https://graph.facebook.com/'
facebook = OAuth2Service(name='facebook',
                         authorize_url='https://www.facebook.com/dialog/oauth',
                         access_token_url=graph_url + 'oauth/access_token',
                         client_id=app.config['FB_CLIENT_ID'],
                         client_secret=app.config['FB_CLIENT_SECRET'],
                         base_url=graph_url)

events = db.Table('events',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('event_id', db.Integer, db.ForeignKey('event.id'), primary_key=True)
)

events_attandance = db.Table('events_attandance',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('event_id', db.Integer, db.ForeignKey('event.id'), primary_key=True)
)
# models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    email = db.Column(db.String(80), nullable=True, default='', unique=True)
    pic_url = db.Column(db.String(150), nullable=True, default='', unique=True)
    phone = db.Column(db.String(15), nullable=True, default='', unique=True)
    github = db.Column(db.String(15), nullable=True, default='', unique=True)
    fb_id = db.Column(db.String(30), nullable=True, unique=True)
    event = db.relationship('Event', secondary=events, lazy='subquery',
        backref=db.backref('user', lazy=True))
    attending = db.relationship('Event', secondary=events_attandance, lazy='subquery',
        backref=db.backref('attandance', lazy=True))

    def __init__(self, name, fb_id):
        self.name = name
        self.fb_id = fb_id
        db.session.add(self)
        db.session.commit()

    def __repr__(self):
        return '<User %r>' % self.name

    def update(self, email=email, pic_url=pic_url, phone=phone, github=github):
        self.email = email
        self.pic_url = pic_url
        self.phone = phone
        self.github = github

        db.session.add(self)
        db.session.commit()

    def save(self):
        db.session.add(self)
        db.session.commit()
        return self.encode_auth_token(self.fb_id)

    @staticmethod
    def get_or_create(fb_id, name=''):
        user = User.query.filter_by(fb_id=fb_id).first()
        if user is None:
            print('creating user')
            user = User(name, fb_id)
            db.session.add(user)
            db.session.commit()
        return user

    def encode_auth_token(self, user_id):
        """
        Encode the Auth token
        :param user_id: User's Id
        :return:
        """
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=app.config.get('AUTH_TOKEN_EXPIRY_DAYS'),
                                                                       seconds=app.config.get(
                                                                           'AUTH_TOKEN_EXPIRY_SECONDS')),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                app.config['SECRET_KEY'],
                algorithm='HS256'
            )
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(token):
        """
        Decoding the token to get the payload and then return the user Id in 'sub'
        :param token: Auth Token
        :return:
        """
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms='HS256')
            # is_token_blacklisted = BlackListToken.check_blacklist(token)
            # if is_token_blacklisted:
            #     return 'Token was Blacklisted, Please login In'
            return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired, Please sign in again'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please sign in again'

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    event_id = db.Column(db.String(30), unique=True)
    attandance_code = db.Column(db.String(10), unique=True)

    def __init__(self, name, event_id, user):
        self.name = name
        self.event_id = event_id
        user.event.append(self)
        db.session.add(user)
        db.session.commit()

    @staticmethod
    def check_attandance(attandance_code, fb_id):
        event = Event.query.filter_by(attandance_code=attandance_code).first()
        if event is not None:
            user = User.query.filter_by(fb_id=fb_id).first()
            user.attending.append(event)
            db.session.add(user)
            db.session.commit()
        return event


# controller
def new_decoder(payload):
    return json.loads(payload.decode('utf-8'))

def token_required(f):
    """
    Decorator function to ensure that a resource is access by only authenticated users`
    provided their auth tokens are valid
    :param f:
    :return:
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return make_response(jsonify({
                    'status': 'failed',
                    'message': 'Provide a valid auth token'
                })), 403

        if not token:
            return make_response(jsonify({
                'status': 'failed',
                'message': 'Token is missing'
            })), 401

        try:
            decode_response = User.decode_auth_token(token)
            current_user = User.query.filter_by(fb_id=decode_response).first()
        except:
            message = 'Invalid token'
            if isinstance(decode_response, str):
                message = decode_response
            return make_response(jsonify({
                'status': 'failed',
                'message': message
            })), 401

        return f(current_user, *args, **kwargs)

    return decorated_function    

# views
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def root(path):
    if path == '':
        return app.send_static_file('index.html')    
    return app.send_static_file(path+'.html')

@app.route('/api/attend', methods=['POST'])
@token_required
def attend(current_user):
    if request.content_type == "application/json":
        data = request.get_json()
        event = Event.check_attandance(data['code'], current_user.fb_id)
        return jsonify({'status':'success', 'message': event.name})
    return jsonify({'status':'failed', 'message': 'Content-type must be json'}), 202

@app.route('/api/user')
@token_required
def user_profile(current_user):
    profile = {
        'name' : current_user.name,
        'email' : current_user.email,
        'pic_url' : current_user.pic_url,
        'upcoming': [],
        'attending': []
    }
    for event in current_user.event:
        detail = {}
        detail['fb_id'] = event.event_id
        detail['name'] = event.name
        detail['code'] = event.attandance_code
        profile['upcoming'].append(detail)

    for event in current_user.attending:
        detail = {}
        detail['fb_id'] = event.event_id
        detail['name'] = event.name
        profile['attending'].append(detail)

    return jsonify({'status':'success', 'message':profile})

@app.route('/api/update/profile', methods=['POST'])
@token_required
def update_profile(current_user):
    if request.content_type == "application/json":
        data = request.get_json()
        print(data)
        current_user.update(phone = data['telp'], github=data['github'])
        return jsonify({'status': 'success'})
    return jsonify({'status':'failed', 'message': 'Content-type must be json'}), 202



@app.route('/facebook/login')
def login():
    redirect_uri = url_for('authorized', _external=True)
    params = {'redirect_uri': redirect_uri}
    return redirect(facebook.get_authorize_url(**params))


@app.route('/facebook/authorized')
def authorized():
    # check to make sure the user authorized the request
    if not 'code' in request.args:
        print('You did not authorize the request')
        return redirect(url_for('root'))

    # make a request for the access token credentials using code
    redirect_uri = url_for('authorized', _external=True)
    data = dict(code=request.args['code'], redirect_uri=redirect_uri)

    session = facebook.get_auth_session(data=data, decoder=new_decoder)

    # the "me" response
    getdata = [
        'name',
        'picture.width(200).height(200)',
        'email',
        'events{name,end_time,start_time}',
        'groups{name,events{name}}'
    ]
    user = session.get('me/?fields=' + ','.join(getdata)).json()

    current_user = User.get_or_create(user['id'], user['name'])
    current_user.update(email=user['email'], pic_url=user['picture']['data']['url'])
    token = current_user.encode_auth_token(current_user.fb_id)
    for event in user['events']['data']:
        try:
            Event(event['name'], event['id'], current_user)
        except:
            db.session.rollback()
            pass
    # current_user add group
    # current_user add event

    # parsing datetime
    # dateparser.parse("2018-05-12T08:00:00+0700") 

    needfill = 'true' if current_user.phone is not None else 'false'
    print(url_for('root', token=token, needfill=needfill))
    return redirect(url_for('root', token=token, needfill=needfill))


if __name__ == '__main__':
    db.create_all()
    app.run()
