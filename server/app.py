#!/usr/bin/env python3

from flask import request, session, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

# @app.before_request
# def check_session():
#     endpoint_list = []

class Signup(Resource):

    def post(self):
        # allow user to signup new account
        request_json = request.get_json()

        username = request_json.get('username')
        password = request_json.get('password')
        image_url = request_json.get('image_url')
        bio = request_json.get('bio')

        new_user = User(
            username = username,
            image_url = image_url,
            bio = bio
        )

        # generates hashed password
        new_user.password_hash = password

        try:

            db.session.add(new_user)
            db.session.commit()

            # sets signed in user to session
            session['user_id'] = new_user.id

            return new_user.to_dict(), 201

        except IntegrityError:
            return {"error:": "422 Unprocessable"}, 422

class CheckSession(Resource):
    
    def get(self):
        user_id = session['user_id']

        user = User.query.filter(User.id == user_id).first()

        if user:
            response = make_response(
                user.to_dict(),
                200
            )
        else:
            response = make_response(
                {},
                401
            )
        return response

class Login(Resource):
    def post(self):

        form_data = request.get_json()

        username = form_data['username']
        password = form_data['password']

        user = User.query.filter(User.username == username).first()

        if user:
            is_authenticated = user.authenticate(password)

            if is_authenticated:
                session['user_id'] = user.id

                response = make_response(
                    user.to_dict(),
                    201
                )
            else:
                response = make_response(
                    {"ERROR": "USER CANNOT LOG IN"},
                    401
                )
        else:
            response = make_response(
                {"ERROR" : "USER NOT FOUND"},
                401
            )
        return response

class Logout(Resource):
    def delete(self):

        if session['user_id'] == None:

            response = make_response(
                {},
                401
            )
        else:
            session['user_id'] = None

            response = make_response(
                {},
                204
            )
        return response

class RecipeIndex(Resource):

    def get(self):
        if 'user_id' not in session:
            return {"error": "User not logged in"}, 401
        
        user_session = session['user_id']
        user = User.query.filter(User.id == user_session).first()
        if not user:
            return {"error": "User not found"}, 401
        
        return [recipe.to_dict() for recipe in user.recipes], 200
    
    def post(self):
        if 'user_id' not in session:
            return {"error": "User not logged in"}, 401
        
        request_json = request.get_json()

        title = request_json.get('title')
        instructions = request_json.get('instructions')
        minutes_to_complete = request_json.get('minutes_to_complete')

        try:
            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=session['user_id']
            )

            db.session.add(recipe)
            db.session.commit()

            return recipe.to_dict(), 201
        
        except IntegrityError:
            return {'error': '422 Unprocessable Entity'}, 422


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)