#!/usr/bin/env python3
import sys
from flask import Flask, jsonify, abort, request, make_response, session
from flask_restful import reqparse, Resource, Api
from flask_session import Session
import json
from ldap3 import Server, Connection, ALL
from ldap3.core.exceptions import *
import pymysql
import pymysql.cursors
import ssl
import settings

app = Flask(__name__)
app.config['SECRET_KEY'] = settings.SECRET_KEY
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_NAME'] = 'peanutButter'
app.config['SESSION_COOKIE_DOMAIN'] = settings.APP_HOST

Session(app)

@app.errorhandler(400) 
def not_found(error):
	return make_response(jsonify( { 'status': 'Bad request' } ), 400)

@app.errorhandler(404)
def not_found(error):
	return make_response(jsonify( { 'status': 'Resource not found' } ), 404)

@app.errorhandler(500)
def not_found(error):
	return make_response(jsonify( { 'status': 'Internal server error' } ), 500)

dbConnection = pymysql.connect(host=settings.DB_HOST,
					user=settings.DB_USER,
					password=settings.DB_PASSWD,
					database=settings.DB_DATABASE,
					charset='utf8mb4',
					cursorclass= pymysql.cursors.DictCursor)

sqlProcName = 'checkUserInDb'

class Root(Resource):
	def get(self):
		return app.send_static_file('index.html')
	
class SignIn(Resource):
	def post(self):

		if not request.json:
			abort(400)

		parser = reqparse.RequestParser()
		try:
			parser.add_argument('username', type=str, required=True)
			parser.add_argument('password', type=str, required=True)
			request_params = parser.parse_args()
		except:
			abort(400)
		
		if request_params['username'] in session:
			response = {'status': 'success'}
			responseCode = 200
		else:
			try:
				ldapServer = Server(host=settings.LDAP_HOST)
				ldapConnection = Connection(ldapServer,
					raise_exceptions=True,
					user='uid='+request_params['username']+', ou=People,ou=fcs,o=unb',
					password = request_params['password'])
				ldapConnection.open()
				ldapConnection.start_tls()
				ldapConnection.bind()
				
			
				cursor = dbConnection.cursor()
				cursor.callproc('checkUserInDb', [request_params['username']])
				
				results = cursor.fetchall()

				for row in results:
					user_exists_in_database = row['count'] > 0
					if(not(user_exists_in_database)):
						cursor.callproc('insertUserIntoDB', [request_params['username']])
						dbConnection.commit()
						print("user added to db -> " , request_params['username'])
					else:
						print("user exists already -> " , request_params['username'])


				session['username'] = request_params['username']
				response = {'Authentication': 'success', 
							'user': request_params['username'],
							}
				responseCode = 201
			except LDAPException:
				response = {'status': 'Access denied'}
				print(response)
				responseCode = 401
			finally:
				ldapConnection.unbind()

		return make_response(jsonify(response), responseCode)

	def get(self):
		if 'username' in session:
			username = session['username']
			response = {'status': 'success'}
			responseCode = 200
		else:
			response = {'status': 'fail'}
			responseCode = 403

		return make_response(jsonify(response), responseCode)
	
	def delete(self):
		if 'username' in session:
			session.clear()
			response = {'status': 'Sign Out Successful' }
			responseCode = 200
		else:
			response = {'status': 'Not Signed In' }
			responseCode = 401

		return make_response(jsonify(response), responseCode)

api = Api(app)
api.add_resource(Root,'/')
api.add_resource(SignIn, '/signin')

if __name__ == "__main__":
	context = ('cert.pem', 'key.pem')
	app.run(
		host=settings.APP_HOST,
		port=settings.APP_PORT,
		ssl_context=context,
		debug=settings.APP_DEBUG)