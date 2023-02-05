from os import access
from src.constants.http_status_code import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_409_CONFLICT
from flask import Blueprint, app, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
import validators
from src.database import User, db
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity

auth = Blueprint("auth", __name__, url_prefix="/api/v1/auth")


@auth.post('/register')
def register():
    username = request.json['username']
    email = request.json['email']
    password = request.json['password']

    if len(password) < 6:
        return jsonify({"error": "password too small"}), HTTP_400_BAD_REQUEST

    if len(username) < 3:
        return jsonify({"error": "username too small"}), HTTP_400_BAD_REQUEST

    if not username.isalnum() or " " in username:
        return jsonify({"error": "username can't be all numeric or have spaces"}), HTTP_400_BAD_REQUEST

    if not username.isalnum() or " " in username:
        return jsonify({"error": "username can't be all numeric or have spaces"}), HTTP_400_BAD_REQUEST

    if not validators.email(email):
        return jsonify({"error": "email is not valid"}), HTTP_400_BAD_REQUEST

    if User.query.filter_by(email=email).first() is not None:
        return jsonify({"error": "email already exits"}), HTTP_409_CONFLICT

    if User.query.filter_by(username=username).first() is not None:
        return jsonify({"error": "username taken"}), HTTP_409_CONFLICT

    pwd_hash = generate_password_hash(password)

    user = User(username=username, password=pwd_hash, email=email)
    db.session.add(user)
    db.session.commit()

    return jsonify({
        'message': "User created",
        'user': {
            'username': username, "email": email
        }

    }), HTTP_201_CREATED


@auth.post('/login')
def login():
    email = request.json.get('email', '')
    password = request.json.get('password', '')

    user = User.query.filter_by(email=email).first()

    if user:
        is_pass_correct = check_password_hash(user.password, password)
        if is_pass_correct:
            refresh = create_refresh_token(identity=user.id)
            access = create_access_token(identity=user.id)
            return jsonify({
                'user': {
                    'refresh': refresh,
                    'access': access,
                    'username': user.username,
                    'email': user.email
                }
            })

    return jsonify({
        'error': 'Wrong Credentials'
    }), HTTP_401_UNAUTHORIZED


@auth.get('/me')
@jwt_required()  # jwt token required to access this
def me():
    user_id = get_jwt_identity()

    user = User.query.filter_by(id=user_id).first()

    return jsonify({
        'username': user.username,
        'email': user.email
    }), HTTP_200_OK


@auth.get('/token/refresh')
@jwt_required(refresh=True)
def refresh_user_token():
    user_identity = get_jwt_identity()
    access = create_access_token(identity=user_identity)

    return jsonify({
        'access': access
    }), HTTP_200_OK
