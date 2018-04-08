import requests, json

######## CHANGE THESE FOR YOUR SCENARIO #########
myURL = "http://localhost:10987"
myAPI = "/api/v1.0"
user_token = "TheseAren'tTheDroidsYouAreLookingFor"
username = 'stupid'
password = 'secret'
####################################


def handshake(session, handshake_data):
    r = session.post(myURL + myAPI + '/handshake', json=handshake_data)
    return r


def post_data(session, data):
    r = session.post(myURL + myAPI, json=data)
    return r


def get_id(session, id):
    r = session.get(myURL + myAPI + '/' + str(id))
    return r


def get_all(session):
    r = session.get(myURL + myAPI)
    return r


def put_id(session, id, data):
    r = session.put(myURL + myAPI + '/' + str(id), json=data)
    return r


def delete_id(session, id):
    r = session.delete(myURL + myAPI + '/' + str(id))
    return r


def login(session):
    r = session.post(myURL + '/login', data={'username': username, 'password': password})
    return r


def logout(session):
    r = session.get(myURL + '/logout')
    return r

def query_data(session, query_string):
    r = session.get(myURL + myAPI + '/query' + query_string)
    return r
def dictionary_content_check(d_subset, d_superset, verbose=True):
    """check if dictionary d1 is all contained in d2: note d2 may have extra items"""
    is_good = True
    for k, v in d_subset.items():
        if d_superset.get(k) != v:
            is_good = False
            if verbose:
                print('unmatched key/value pair key={}, value={}'.format(k, v))
    if verbose:
        if is_good:
            print("PASSED content check")
        else:
            print("FAILED content check")

    return is_good


def test_status_return(test_description, resp, pass_code):
    msg = "STATUS <{}>".format(test_description)
    if resp.status_code == pass_code:
        msg = "PASS " + msg + " (expected and received {})".format(pass_code)
    else:
        msg = "FAIL " + msg + " (returned {}, but should be {})".format(resp.status_code, pass_code)
    return msg


def test_content_return(test_description, resp, content):
    msg = "CONTENT <{}>".format(test_description)
    if content in resp.content:
        msg = "PASS " + msg
    else:
        msg = "FAIL " + msg
    return msg


if __name__ == '__main__':
    # keeping a persistent session.
    session = requests.Session()

    # test logout first, in case we are already logged in
    r = logout(session)
    print(test_status_return("Logout()", r, 200))
    print(test_content_return("Logout()", r, "you are logged out"))

    # test login
    r = login(session)
    print(test_status_return("Logout() -> Login()", r, 200))
    print(test_content_return("Logout()-> Login()", r, "private token"))

    # logout, then a handshake
    r = logout(session)
    bad_handshake = "something's wrong with this handshake"
    r = handshake(session, bad_handshake)
    print(test_status_return("Handshake() with INVALID data", r, 400))

    r = logout(session)
    invalid_user_token_handshake = {'user_token': 'not a good token'}
    r = handshake(session, invalid_user_token_handshake)
    print(test_status_return("Handshake() with bad token", r, 404))

    r = logout(session)
    good_handshake = {'user_token': user_token}
    r = handshake(session, good_handshake)
    print(test_status_return("Handshake() with valid user_token", r, 201))

    simple_data = {'name': 'Bart Simpson', 'age': 10, 'home': 'Springfield'}
    r = post_data(session, simple_data)
    print(test_status_return("post_data() simple", r, 201))
    print(test_content_return("post_data() simple", r, 'Bart Simpson'))

    # have to get it from inside object and data containers
    simple_object = json.loads(r.content).get('object')
    simple_id = simple_object['id']
    dictionary_content_check(simple_data, simple_object['data'])

    r = get_all(session)
    print(test_status_return("get_all()", r, 201))
    print(test_content_return("get_all()", r, "Bart Simpson"))

    r = get_id(session, simple_id)
    print(test_status_return("get_id()", r, 201))
    print(test_content_return("get_id()", r, 'Bart Simpson'))
    simple_object = json.loads(r.content).get('object')
    dictionary_content_check(simple_data, simple_object.get('data'))

    # add some data to test query
    simple_object2 = {'name': 'Lisa Simpson', 'age': 9, 'home': 'Springfield'}
    simple_object3 = {'name': 'Homer Simpson', 'age': 40, 'home': 'Springfield'}
    simple_object4 = {'name': 'Batman', 'age':34, 'home': 'Gotham City'}
    r2 = post_data(session, simple_object2)
    r3 = post_data(session, simple_object3)
    r4 = post_data(session, simple_object4)

    # lets query these objects
    r = query_data(session, '?home=Springfield')
    print(test_status_return("query_data() simple", r, 201))
    query_object = json.loads(r.content).get('array')
    print("*** Query(home is SpringField)")
    for item in query_object:
        print(item)

    r = query_data(session, '?home!=Springfield')
    query_object = json.loads(r.content).get('array')
    print("*** Query(NOT home Springfield)")
    for item in query_object:
        print(item)

    this_id = json.loads(r2.content)['object']['id']
    r = delete_id(session, this_id)
    this_id = json.loads(r3.content)['object']['id']
    r = delete_id(session, this_id)
    this_id = json.loads(r4.content)['object']['id']
    r = delete_id(session, this_id)
    del r2
    del r3
    del r4

    # get something that doesn't exist
    r = get_id(session, 100000)
    print(test_status_return("get_id() nonexistent data", r, 404))

    # store and retrieve medium complexity item
    medium_data_item = {
        "rid": 1,
        "work": {
            "id": 10,
            "name": "Miroirs",
            "composer": {
                "id": 100,
                "name": "Maurice Ravel",
                "functions": ["Composer"]
            }
        },
        "recording_artists": [
            {
                "id": 101,
                "name": "Alexandre Tharaud",
                "functions": ["Piano"]
            },
            {
                "id": 102,
                "name": "Jean-Martial Golaz",
                "functions": ["Engineer", "Producer"]
            }
        ]
    }

    # post medium complexity data item to database
    r = post_data(session, medium_data_item)
    medium_object = json.loads(r.content).get('object')
    medium_id = medium_object.get('id')
    print(test_status_return('post_data() medium complexity item', r, 201))

    # get it back
    r = get_id(session, medium_id)
    print(test_status_return('post_data() -> get_id() medium complexity item', r, 201))
    print(test_content_return('post_data() -> get_id() medium complexity item', r, 'Maurice Ravel'))

    # deep content check
    medium_object = json.loads(r.content).get('object')
    dictionary_content_check(medium_data_item, medium_object['data'])

    # before we delete, lets try a fetch all and make sure we find simple and medium complexity items
    r = get_all(session)
    print(test_status_return('get_all() "are both our items present" test', r, 201))
    print(test_content_return('get_all() "are both our items present" test part 1', r, 'Bart Simpson'))
    print(test_content_return('get_all() "are both our items present" test part 2', r, 'Maurice Ravel'))

    # delete the medium complexity item
    r = delete_id(session, medium_id)
    print(test_status_return('delete_id() medium complexity item', r, 201))

    # attempt to fetch the deleted item should return a 404
    r = get_id(session, medium_id)
    print(test_status_return('delete_id()->get_id() medium complexity item', r, 404))

    # delete the simple item
    r = delete_id(session, simple_id)
    print(test_status_return('delete_id() simple item', r, 201))

    # attempt to fetch the deleted item should return a 404
    r = get_id(session, simple_id)
    print(test_status_return('delete_id()->get_id() medium complexity item', r, 404))

    # now these items are deleted, lets try a fetch all and make sure we DONT find simple and medium complexity items
    r = get_all(session)
    print("*** NOTE: these next tests should FAIL if delete occurred properly")
    print(test_content_return('get_all() "are both our items DELETED" test part 1', r, 'Bart Simpson'))
    print(test_content_return('get_all() "are both our items DELETED" test part 2', r, 'Maurice Ravel'))

    # put test (first put some data in there to read)
    r = post_data(session, simple_data)
    simple_object = json.loads(r.content).get('object')
    simple_id = simple_object.get('id')
    simple_object_data = simple_object.get('data')
    # add the catchPhrase to the object, put it back into the database
    simple_object_data['catchPhrase'] = 'Eat my shorts'
    r = put_id(session, simple_id, simple_object_data)
    print(test_status_return('put_data()', r, 201))
    # get it back out to make sure content was modified properly
    r = get_id(session, simple_id)
    print(test_content_return('put_id() -> get_id()', r, 'Eat my shorts'))
    # now, do a more extensive content check
    simple_object = json.loads(r.content).get('object')
    dictionary_content_check(simple_object_data, simple_object['data'])

    # clean up last item
    r = delete_id(session, simple_id)


