# flask-json-server

This is a simple Flask-based JSON server

Flask simple JSON "database" server. (Spring 2018)

A work in progress

#What it is:

A single-file lightweight JSON server that uses Flask and Peewee ORM
requires Python 2.7.x, Flask, Flask-bcrypt, Peewee, requests, tornado

It would be trivial for someone to port to Python 3.5+

Flask is a great way to build a lightweight/fast API.  This might serve
as some sample code for someone learning what to do (and what not to do).

Serious Flaskonistas should use Flask-RESTful!

Peewee will allow either a SQLite or Postgres database backends,
for now it will use SQLite since I am not sure if there is any
value in this code other than a demonstration of CRUD API that
should accept generic session oriented interaction.

# Intent:

This was written to be a lightweight daemon (to be run with Tornado or Gunicorn).
It should be easy enough to be accessed by Javascript (think AJAX) or Python.
But really programs written in any language that supports http requests
such as Java, .NET, Ruby, etc. would work as a client.

Proof of concept will be a Blog site written with
REACT components, and possibly demonstration projects associated with calendar
maintenance.

By default, the service provides a CRUD API on port 10987
http://localhost:10987/api/v1.0

## CLI (Command Line Interface) launch options

--initialize (creates tables for first-use)

--createadmin or --createsuperuser (creates an administrative user which can access ADMIN API)

--createuser (creates a regular user, can store data on the system)

--token (spits out a token that can be used... in reality any string can serve as a token)

--drop User (blows away entire user table, no backup made! Use with caution.)

--drop DataObj (blows away the entire data objects table, no safety net!! Use with extreme caution!)


requires a valid user_token to establish data objects in the SqliteDatabase

# Tornado Server Deployment

I found that Flask had some stuttering behavior when I used Postman and Chrome and Microsoft Edge browsers against
the Flask development server session. 
Flask will appear to "hang" each time a new client attempts a connection.
This is due to the "blocking" nature of the Flask dev server.

I would normally turn to using Gunicorn, but it has not been ported to Windows.
So instead I use the very excellent Tornado Web Server

http://www.tornadoweb.org

(Other great options are "Twisted", and "Waitress")

> 

