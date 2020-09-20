# Task-Management
A simple Task Management backend application using Flask

All endpoints has been tested with Postman, and the collection will also be available in this repository.
You can log in as default users with different access levels
1. admin
username: admin
password: admin

2. user
username: Naufal
password: password

Every endpoint is NOT accessible without logging in, except Create User and, of course, Login.
After logging in, make sure to copy the access token returned, and paste it to x-access-token header in every endpoint

You can create a new user without logging in, but the new user will have "user" access level.
However, admin can promote each user to have "admin" access level.

When logged in with "admin" access level you will have access to most of the endpoints, including:
1. Get All Task
2. Create Task
3. Revoke Task
4. Delete Task

Users with "user" access level will only have access to these endpoints:
1. Get All Task
2. Get Task
3. Reserve Task
4. Get Reserved Task
5. Complete Task

# Setup
These are the packages you need to install before running this application
pip install flask

pip install flask_sqlalchemy

pip install PyJWT

pip install datetime

# Execution
To run ths application type these in the terminal

export FLASK_APP=api.py

flask run
