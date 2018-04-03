"""
Flask simple JSON "database" server. (Spring 2018)

A work in progress

Jeff Muday

What it is: a single-file lightweight JSON server that uses Flask and Peewee ORM
requires Python 2.7.x, Flask, Flask-bcrypt, Peewee, requests

It would be trivial for someone to port to Python 3.5+

Flask is a great way to build a lightweight/fast API.  This might serve
as some sample code for someone learning what to do (and what not to do).

Serious Flaskonistas should use Flask-RESTful!

Peewee will allow either a SQLite or Postgres database backends,
for now it will use SQLite since I am not sure if there is any
value in this code other than a demonstration of CRUD API that
should accept generic session oriented interaction.

Intent:
This was written to be a lightweight daemon (to be run with Tornado or Gunicorn).
It should be easy enough to be accessed by Javascript (think AJAX) or Python.
But really programs written in any language that supports http requests
such as Java, .NET, Ruby, etc. would work as a client.

Proof of concept will be a Blog site written with
REACT components, and possibly demonstration projects associated with calendar
maintenance.

By default, the service provides a CRUD API on port 10987
http://localhost:10987/api/v1.0

Command Line launch options

--initialize (creates tables for first-use)
--createadmin or --createsuperuser (creates an administrative user which can access ADMIN API)
--createuser (creates a regular user, can store data on the system)
--token (spits out a token that can be used... in reality any string can serve as a token)
--drop User (blows away entire user table, no backup made! Use with caution.)
--drop DataObj (blows away the entire data objects table, no safety net!! Use with extreme caution!)


requires a valid user_token to establish data objects in the SqliteDatabase

"""
from functools import wraps
from flask import (abort, Flask, g, jsonify, make_response,
                   redirect, render_template, request,
                   session, url_for)

from flask_bcrypt import generate_password_hash, check_password_hash

from peewee import *
from playhouse.shortcuts import model_to_dict
import datetime, random, string, sys, os, getpass, json

def token_generator(size=12, chars=string.ascii_uppercase + string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

app = Flask(__name__)
app.secret_key = "rx3$hYE08JCYc*&^Jnb^%$"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'dataobjects.db')
DB = SqliteDatabase(DB_PATH)
PORT = 10987
DEBUG = False
HOST = '0.0.0.0'

class JSONField(TextField):
    def db_value(self, value):
        return json.dumps(value)

    def python_value(self, value):
        if value is not None:
            return json.loads(value)
        
class DataObj(Model):
    data = JSONField()
    user_token = CharField()
    read_token = CharField(default="") # owner can set a token to read
    write_token = CharField(default="") # owner can set a token to post/delete
    timestamp = DateTimeField(default=datetime.datetime.now)
    token_required = BooleanField(default=True)

    class Meta:
        database = DB

class User(Model):
    username = CharField(unique=True)
    email = CharField(default='')
    password = CharField()
    token = CharField()
    is_admin = BooleanField()

    def __repr__(self):
        return username

    def authenticate(self, password):
        """basic password authentication"""
        try:
            if check_password_hash(self.password, password):
                return True
        except:
            """a particular error flags that a user does not have an encrypted password, fix it here"""
            self.encrypt_password()

    def encrypt_password(self, password=None, commit=True):
        """encrypts a password (bcrypt)"""
        if password:
            hashed_pw = generate_password_hash(password)
        else:
            hashed_pw = generate_password_hash(self.password)
        self.password = hashed_pw
        if commit:
            self.save()

    def set_token(self, token=None):
        """sets a token for the user, probably should propagate a token change on the data"""
        if token:
            self.token = token
        else:
            self.token = token_generator()
        return self.token

    class Meta:
        database = DB

def confirm(msg, response):
    """CLI confirmation dialog"""
    print(msg)
    user = raw_input("type {} to confim: ".format(response))
    if user==response:
        return True

    print('CANCELLED')
    return False
        
def initialize(args):
    """handle initialization with arguments"""
    DB.connect()
        
    if len(args) > 1:

        if '--createadmin' in args or '--createsuperuser' in args:
            """create admin user from command line"""
            create_user(is_admin=True)
    
        if '--createuser' in args:
            """create admin user from command line"""
            create_user(is_admin=False)
            
        if '--drop' in args:
            if 'DataObj' in args:
                if confirm('Drop DataObj table?', 'DELETE'):
                    DB.drop_tables([DataObj])
                    print("DataObj table dropped.")
            
            if 'User' in args:
                if confirm('Drop USER table?', 'DELETE'):
                    DB.drop_tables([User])
                    print("User table dropped")
            
        
        if '--initialize' in args:
            DB.create_tables([DataObj, User], safe=True)
            print("tables created")
            
        DB.close()
        print("Exiting")
        sys.exit(0)
        
    # Safety Check ensure the tables are in the database
    DB.create_tables([DataObj, User], safe=True)
        
    users = User.select()
    if len(users) < 1:
        print("You have no users!  Please use '--createadmin' or '--createuser' command line option to get started") 
        print("Exiting")
        sys.exit(0)
        
    DB.close()
    

def get_object_or_404(cls, object_id):
    try:
        return cls.get(cls.id==object_id)
    except:
        abort(404)

def query_to_dict(query, verbose=False):
    """turn a query into an array of dictionaries"""
    array = []
    for item in query:
        # inject actual table id-- useful!
        item.data['id'] = item.id
        if verbose:
            array.append(model_to_dict(item))
        else:
            array.append(item.data)
    return array

@app.before_request
def before_request():
    g.db = DB
    g.db.connect()

@app.after_request
def after_request(response):
    g.db.close()
    return response

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)


def handshake_required(f):
    """a decorator ensures that a handshake has taken place and a user token or read token is present in the session"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not(session.get('read_token')) and not(session.get('user_token')):
            return make_response(jsonify({'error': 'handshake session missing'}), 404)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/v1.0/handshake', methods=['POST'])
def api_handshake():
    """handshake accepts tokens-- and puts them in the session cookie.  user_token is checked and only inserted if it is valid"""
    if not request.json:
        abort(400)
        
    # get data that was sent to us
    data = request.get_json()
    
    # get tokens from the data (if any are there)
    read_token = data.get('read_token', '')
    write_token = data.get('write_token', '')
    user_token = data.get('user_token', '')
    
    if user_token == "" and read_token == "":
        # die if they didn't send either a user_token or read_token
        abort(400)
    
    # if present, inject token into the session.
    if read_token:
        session['read_token'] = read_token
    if write_token:
        session['write_token'] = write_token
        
    if user_token:
        # user token is ONLY put into the session if it MATCHES a real user.
        # maybe remove in finished server, for now, it will help identify that no user has that token
        try:
            user = User.get(User.token==user_token)
            session['user_token'] = user_token
        except:
            # in the future might want to fail silently
            return make_response(jsonify({'error': 'No matching user_token'}), 404)
    
    return jsonify({'token(s) established': 'Ok'}), 201
    
def get_tokens(data={}):
    """get the tokens from the JSON data or session -- JSON overrides the session token"""
    data_tokens = data.get('user_token', None), data.get('read_token', None), data.get('write_token',None)
    session_tokens = session.get('user_token', None), session.get('read_token', None), session.get('write_token',None)
    # data tokens will override session tokens
    for i in range(0,3):
        if data_tokens[i]:
            session_tokens[i] = data_tokens[i]
    return session_tokens

@app.route('/api/v1.0', methods=['POST'])
@handshake_required
def api_post():
    """create a DataObj from a POST (json) request"""
    if not request.json:
        abort(400)
        
    # get the data sent to us    
    data = request.get_json()
    
    # get tokens, only a user token can write NEW
    # the read_token and write_tokens will be written if they are present
    # ***NOTE*** we skip the validity check on an overridden user_token,
    # this might be a good for flexibility, bad for security
    user_token, _, _ = get_tokens(data)
    
    if user_token:
        # only (valid) users are allowed to write data,
        # validity was established when handshake took place
        try:
            obj = DataObj.create(data=data, user_token=user_token)
            return jsonify({'object': model_to_dict(obj)}), 201
        except Exception as e:
            print(e)
    else:
        return make_response(jsonify({'error': 'no handshake data in session'}), 400)
        
    return make_response(jsonify({'error': 'data create failed'}), 400)

@app.route('/api/v1.0', methods=['GET'])
@handshake_required
def api_get_all():
    """return all user_token objects and read_token objects (tokens are from session)"""
    # ***NOTE*** might want to add ability to send a cookie from client (sessionless)
    
    user_token, read_token, _ = get_tokens()
    
    # must have either a specific user_token or read_token to allow a query
    if user_token != "" or read_token != "":
        try:
            # read all objects that match the read_token or user_token
            data = DataObj.select().where( (DataObj.read_token==read_token) | (DataObj.user_token==user_token) )
            return jsonify({'objects':query_to_dict(data)}), 201
        except Exception as e:
            print(e)
    
    return make_response(jsonify({'error': 'data READ failed'}), 400)

@app.route('/api/v1.0/<int:id>', methods=['GET'])
@handshake_required
def api_get(id):
    """get an object with a particular id, token limited access"""
    # get tokens
    user_token, read_token, _ = get_tokens()
    
    # get object or fail
    obj = get_object_or_404(DataObj, id)
    
    # determine if token(s) allow access
    can_read = (read_token == obj.read_token) or (user_token == obj.user_token)
    
    if can_read:
        obj.data['id'] = obj.id # inject the id into the data, useful!
        return jsonify({'object': obj.data}), 201
    
    make_response(jsonify({'error': 'data GET failed'}), 400)

@app.route('/api/v1.0/<int:id>', methods=['PUT'])
@handshake_required
def api_put(id):
    """PUT allows change of an existing id JSON data"""
    if not request.json:
        abort(400)        
    
    # get JSON sent to us
    data = request.get_json()
    
    # get existing object or die
    obj = get_object_or_404(DataObj, id)
    
    # get tokens from session and/or data
    user_token, read_token, write_token = get_tokens(data)
    
    # determine if user can PUT (update) the object based on user_token and/or write_token
    can_write = (obj.user_token == user_token) or (obj.write_token == write_token)
    
    if can_write:
        try:
            obj.data = data
            obj.save()
            obj.data['id'] = obj.id # inject id into data, useful!
            return jsonify({'object': obj.data}), 201
        except Exception as e:
            print(e)
        
    return make_response(jsonify({'error': 'data PUT failed'}), 400)

@app.route('/api/v1.0/<int:id>', methods=['DELETE'])
@handshake_required
def api_delete(id):
    """delete an id, must have an active handshake that matches the user or write token of the data id"""
    # get existing object or die
    obj = get_object_or_404(DataObj, id)
    
    # get tokens from session, maybe add cookie for sessionless access?
    user_token, read_token, write_token = get_tokens()
    
    # determine if user can PUT (update) the object
    can_delete = (obj.user_token == user_token) or (obj.write_token == write_token)
    
    if can_delete:
        obj_data = obj.data # save data to be returned
        obj_data['id'] = obj.id # inject the id, probably not needed at this point
        try:
            obj.delete_instance()
            return jsonify({'object': obj_data}), 201
        except Exception as e:
            print(e)
    
    return make_response(jsonify({'error': 'data DELETE failed'}), 400)

@app.route('/api/v1.0/query', methods=['GET'])
@handshake_required
def api_query():
    """query based on key/value pairs which come via query string"""
    
    # get session tokens
    # ***NOTE*** might want to ONLY look for read_token data if user has multiple read_tokens which disambiguate data sets
    user_token, read_token, _ = get_tokens()
    
    try:
        all_objects = DataObj.select().where( (DataObj.read_token==read_token) | (DataObj.user_token==user_token) )
    except Exception as e:
        print(e)
        return make_response(jsonify({'error': 'data READ failed'}), 400)  
    
    # now, we build our
    selected_objects = []
    for obj in all_objects:
        for k,v in request.args.items():
            if str(obj.data.get(k)) == v:
                obj.data['id'] = obj.id # inject id, useful!
                selected_objects.append(obj.data)
    
    return jsonify({'objects': selected_objects }), 201            
    

@app.route('/')
def index():
    """view shows server is running and server time"""
    return "Server running @ {}".format(datetime.datetime.now())

@app.route('/login', methods=['GET','POST'])
def login():
    """basic login, simple, unstyled."""
    error = ""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.select().where(User.username==username)
        if len(user):
            user = user[0]
            if user.authenticate(password):
                # correct login, set the session
                session['user_id'] = user.id
                session['user_token'] = user.token
                return redirect('profile')
            
        error = "Username or password incorrect"
        
    
    return """
    <form method="POST">
    Username<br />
    <input type="text" name="username" /><br />
    Password<br />
    <input type="password" name="password" /><br /><br />
    <input type="submit" /><br>
    </form>
    <font color="red">{}</font>
    """.format(error)

@app.route('/profile')
def profile():
    """give the user some basic information about their account"""
    user_id = session.get('user_id',None)
    if user_id is None:
        abort(404)
    user = get_object_or_404(User, user_id)
    data = DataObj.select().where(DataObj.user_token==user.token)
    return """
    <p>Welcome {}.</p>
    <p>Your private token is: {}</p>
    <p>You have {} data objects in the store</p>
    <p><a href="{}">show objects</a></p>
    """.format(user.username, user.token, len(data), url_for('api_get_all'))
    
@app.route('/logout')
def logout():
    """basic logout, not much to see here"""
    session.clear()
    return "you are logged out"

def create_user(is_admin=False):
    """create a user from CLI"""
    if is_admin:
        message = 'Enter ADMIN username (blank to cancel) : '
    else:
        message = 'Enter username (blank to cancel) : '
    username = raw_input(message)
    if username == "":
        print("create user CANCELLED")
        sys.exit(0)
        
    password = getpass.getpass()
    if password == "":
        print("create user CANCELLED")
        sys.exit(0)
        
    try:
        user = User(username=username, password=password, is_admin=is_admin, token='_')
        user.set_token()
        user.encrypt_password()
        user.save()
        print("user created.")
    except Exception as e:
        print("ERROR: {}".format(e))
    

if __name__ == '__main__':
    initialize(sys.argv)
    app.run(host=HOST, port=PORT, debug=DEBUG)
