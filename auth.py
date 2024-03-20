from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt, current_user, get_jwt_identity
from models import User, TokenBlocklist
from extensions import jwt

auth_bp = Blueprint('auth', __name__)

@auth_bp.post('/register')
def register_user():

    data = request.get_json()
    user = User.get_user_by_username(username = data.get('username'))
    if user is not None:
        return jsonify({'message': 'User already exists'}), 403

    new_user = User(
        username = data.get('username'),
        email = data.get('email')
    )    
    
    new_user.set_password(password = data.get('password_hash'))
    new_user.save()
    return jsonify({'message': 'User registered'}) , 201

@auth_bp.post('/login')
def login_user():

    data = request.get_json()
    user = User.get_user_by_username(username = data.get('username'))

    if user and (user.check_password(password = data.get('password_hash'))):
        access_token = create_access_token(identity = user.username)
        refresh_token = create_refresh_token(identity = user.username)
        return jsonify(
            {
                'message': 'Logged In', 
                'tokens': {
                    'access': access_token,
                    'refresh': refresh_token,
                }
            }
        ), 200
    
    return jsonify({'error': 'Invalid username or password'}), 400

@auth_bp.get('/whoami')
@jwt_required()
def whoami():
    return jsonify({'message':"message", "user_details":{"username":current_user.username, "email":current_user.email}}), 200

@auth_bp.get('/refresh')
@jwt_required(refresh=True)
def refresh_access():
    identity = get_jwt_identity()
    new_access_token = create_access_token(identity = identity)
    return jsonify({'access_token':new_access_token}), 200

@auth_bp.get('/logout')
@jwt_required(verify_type=False)
def logout_user():
    jti = get_jwt()['jti']
    token_type = jwt()['type']
    token = TokenBlocklist(jti = jti)
    token.save()
    return jsonify({'message': f'{token_type} Token revoked succesfully'}), 200