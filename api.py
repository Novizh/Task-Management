from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///task-management.db'
app.config['JSONIFY_MIMETYPE'] = 'application/json'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(80))
    access_level = db.Column(db.String(50))

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_name = db.Column(db.String(50))
    description = db.Column(db.String(50))
    status = db.Column(db.String(50))
    user_id = db.Column(db.Integer)

def token_required(check):
    @wraps(check)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(id=data['id']).first()
        
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return check(current_user, *args, **kwargs)
    
    return decorated

@app.route('/user', methods=['POST'])
@token_required
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    access_level = "user"
    new_user = User(username=data['username'], password=hashed_password, access_level=access_level)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message" : "New user created!"})

@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(username=auth.username).first()
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'id' : user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=15)}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.access_level == 'admin':
        return jsonify({'message' : 'Access denied!'})

    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['id'] = user.id
        user_data['username'] = user.username
        user_data['password'] = user.password
        user_data['access_level'] = user.access_level
        output.append(user_data)
    return jsonify({'users' : output})

@app.route('/user/<id>', methods=['GET'])
@token_required
def get_user(current_user, id):
    if not current_user.access_level == 'admin':
        return jsonify({'message' : 'Access denied!'})

    user = User.query.filter_by(id=id).first()
    if not user:
        return jsonify({"message" : "User not found!"})
    
    user_data = {}
    user_data['id'] = user.id
    user_data['username'] = user.username
    user_data['password'] = user.password
    user_data['access_level'] = user.access_level
    return jsonify({'user' : user_data})

@app.route('/user/<id>', methods=['PUT'])
@token_required
def promote_user(current_user, id):
    if not current_user.access_level == 'admin':
        return jsonify({'message' : 'Access denied!'})

    user = User.query.filter_by(id=id).first()
    if not user:
        return jsonify({"message" : "User not found!"})

    user.access_level = "admin"
    db.session.commit()
    return jsonify({"message" : "User promotion successful!"})

@app.route('/user/<id>', methods=['DELETE'])
@token_required
def delete_user(current_user, id):
    if not current_user.access_level == 'admin':
        return jsonify({'message' : 'Access denied!'})
        
    user = User.query.filter_by(id=id).first()
    if not user:
        return jsonify({"message" : "User not found!"})

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message" : "User deletion successful!"})

@app.route('/task', methods=['POST'])
@token_required
def create_task(current_user):
    if not current_user.access_level == 'admin':
        return jsonify({'message' : 'Access denied!'})

    data = request.get_json()
    status = "Not Done"
    new_task = Task(task_name=data['task_name'], description=data['description'], status=status)
    db.session.add(new_task)
    db.session.commit()
    return jsonify({'message' : 'New task created!'})

@app.route('/task', methods=['GET'])
@token_required
def get_all_tasks(current_user):
    tasks = Task.query.all()
    output = []
    for task in tasks:
        task_data = {}
        task_data['id'] = task.id
        task_data['task_name'] = task.task_name
        task_data['description'] = task.description
        task_data['status'] = task.status
        task_data['user_id'] = task.user_id
        output.append(task_data)
    return jsonify({'task' : output})

@app.route('/task/<task_id>', methods=['GET'])
@token_required
def get_task(current_user, task_id):
    task = Task.query.filter_by(id=task_id).first()
    if not task:
        return jsonify({'message' : 'Task not found!'})

    task_data = {}
    task_data['id'] = task.id
    task_data['task_name'] = task.task_name
    task_data['description'] = task.description
    task_data['status'] = task.status
    task_data['user_id'] = task.user_id
    return jsonify({'task' : task_data})

@app.route('/task/reserve/<task_id>', methods=['PUT'])
@token_required
def reserve_task(current_user, task_id):
    task = Task.query.filter_by(id=task_id).first()
    if not task:
        return jsonify({'message' : 'Task not found!'})

    if not task.user_id == None:
        return jsonify({'message' : 'This task has been reserved by other user!'})

    task.user_id = current_user.id
    db.session.commit()
    return jsonify({'message' : 'Task reservation successful!'})

@app.route('/task/personal-task', methods=['GET'])
@token_required
def get_reserved_tasks(current_user):
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    if not tasks:
        return jsonify({'message' : 'You have no tasks!'})

    output = []
    for task in tasks:
        task_data = {}
        task_data['id'] = task.id
        task_data['task_name'] = task.task_name
        task_data['description'] = task.description
        task_data['status'] = task.status
        task_data['user_id'] = task.user_id
        output.append(task_data)
    return jsonify({'task' : output})

@app.route('/task/complete/<task_id>', methods=['PUT'])
@token_required
def complete_task(current_user, task_id):
    task = Task.query.filter_by(id=task_id).first()
    if not task:
        return jsonify({'message' : 'Task not found!'})

    if task.user_id == None:
        return jsonify({'message' : 'This task has not been reserved!'})

    task.status = "Done"
    db.session.commit()
    return jsonify({'message' : 'Task completion successful!'})

@app.route('/task/revoke/<task_id>', methods=['PUT'])
@token_required
def revoke_reserved_task(current_user, task_id):
    if not current_user.access_level == 'admin':
        return jsonify({'message' : 'Access denied!'})

    task = Task.query.filter_by(id=task_id).first()
    if not task:
        return jsonify({'message' : 'Task not found!'})

    if task.user_id == None:
        return jsonify({'message' : 'This task has not been reserved!'})

    if task.status == "Done":
        return jsonify({'message' : 'This task has been done!'})

    task.user_id = None
    db.session.commit()
    return jsonify({'message' : 'Task revoke successful!'})

@app.route('/task/<task_id>', methods=['DELETE'])
@token_required
def delete_task(current_user, task_id):
    if not current_user.access_level == 'admin':
        return jsonify({'message' : 'Access denied!'})
    
    task = Task.query.filter_by(id=task_id).first()
    if not task:
        return jsonify({'message' : 'Task not found!'})

    db.session.delete(task)
    db.session.commit()
    return jsonify({'message' : 'Task deletion successful!'})

if __name__ == '__main__':
    app.run(debug=True)