#### tserver.py ##########
#
# very simple Tornado server for app.app
#
# Jeff Muday (Spring 2018)
#
# I prefer Gunicorn, but this will work on Windows!
#
import sys
from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
# change this app below to your flask app
from app import app

# default port
PORT = 8080

if __name__ == '__main__':
    # User override launch of port
    if '--port' in sys.argv:
        try:
            PORT = int(sys.argv[sys.argv.index('--port')+1])
        except Exception as e:
            print(e)
            print("ERROR: port value must be an integer")
            sys.exit(0)

    print("Starting Tornado Server on port %s" % PORT)
    http_server = HTTPServer(WSGIContainer(app))
    http_server.listen(PORT)
    IOLoop.instance().start()
