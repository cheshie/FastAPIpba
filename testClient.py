from fastapi import FastAPI
from fastapi.encoders import jsonable_encoder
from fastapi.testclient import TestClient
from main import app
from datetime import datetime
from uuid import uuid4
from models import User
from json import loads
from base64 import b64encode
from requests import request
from jose import jws
from time import sleep
import hmac
from hashlib import sha256
from binascii import hexlify

client = TestClient(app)


# Correct scenarios # # # # # #
# Add user
def test_add_user(user):
    requestHeader=dict(requestId=str(uuid4()), sendDate=str(datetime.now().isoformat()))
    response = client.post(
                "/users", 
                headers={'Content-Type' : 'application/json' },
                json=dict(requestHeader=requestHeader, user=jsonable_encoder(user))
    )
    print("[*] Adding user returned: ", response.status_code)
    assert response.status_code == 200

# Check if there is enough users in db
def test_get_list_of_users(numberOfAddedUsers):
    response = client.get("/users", params=dict(requestId=str(uuid4()), sendDate=datetime.now().isoformat()))
    print("[*] Getting list of users returned: ", response.status_code)
    assert response.status_code == 200
    # 3 users added successfully
    print("[*] Number of users in db: ", len(response.json()['usersList']))
    assert len(response.json()['usersList']) == numberOfAddedUsers

# Check if specific user exists in db
def test_get_specific_user(userId):
    response = client.get(f"/users/{userId}", params=dict(requestId=str(uuid4()), sendDate=datetime.now().isoformat()))
    print("[*] Getting specific user returned: ", response.status_code )
    assert response.status_code == 200

# Check if test is able to modify specific user and new user name (returned) is as expected
def test_modify_specific_user(newUser, userId, newName):
    requestHeader=dict(requestId=str(uuid4()), sendDate=str(datetime.now().isoformat()))
    response = client.put(
                f"/users/{userId}", 
                headers={'Content-Type' : 'application/json' },
                json=dict(requestHeader=requestHeader, user=jsonable_encoder(newUser))
    )
    print("[*] User modified successfully. Code: ", response.status_code, " Changed name: ", response.json()['user']['name'])
    assert response.status_code == 200
    assert response.json()['user']['name'] == newName

# Test if able to delete specific user
def test_delete_specific_user(userId):
    response = client.delete(f"/users/{userId}", params=dict(requestId=str(uuid4()), sendDate=datetime.now().isoformat()))
    print("[*] Removing specific user returned: ", response.status_code)
    assert response.status_code == 200
# Correct scenarios # # # # # #

# Incorrect scenarios # # # # # #
# Add user that already exists
def test_add_user_already_exists(user):
    requestHeader=dict(requestId=str(uuid4()), sendDate=str(datetime.now().isoformat()))
    response = client.post(
                "/users", 
                headers={'Content-Type' : 'application/json' },
                json=dict(requestHeader=requestHeader, user=jsonable_encoder(user))
    )
    print("[*] Adding EXISTING user returned: ", response.status_code, " Response message: ", response.text)
    assert response.status_code == 422

# Get user with ID that does not exist in db
def test_get_user_does_not_exist(userId):
    response = client.get(f"/users/{userId}", params=dict(requestId=str(uuid4()), sendDate=datetime.now().isoformat()))
    print("[*] Getting user that does not exist returned: ", response.status_code, " Response message: ", response.text)
    assert response.status_code == 422

def test_modify_user_does_not_exist(newUser, userId):
    requestHeader=dict(requestId=str(uuid4()), sendDate=str(datetime.now().isoformat()))
    response = client.put(
                f"/users/{userId}", 
                headers={'Content-Type' : 'application/json' },
                json=dict(requestHeader=requestHeader, user=jsonable_encoder(newUser))
    )
    print("[*] User that does not exist was tried to be modified. Code: ", response.status_code, " Response message: ", response.text)
    assert response.status_code == 422

def test_delete_user_that_does_not_exist(userId):
    response = client.delete(f"/users/{userId}", params=dict(requestId=str(uuid4()), sendDate=datetime.now().isoformat()))
    print("[*] Removing user that does not exist returned: ", response.status_code, " Response message: ", response.text)
    assert response.status_code == 422

def test_api():
    userId1 = '12345678-1234-5678-1234-567812345678'
    userId2 = '22345678-1234-5678-1234-567812345678'
    userId3 = '32345678-1234-5678-1234-567812345678'
    usr1 = User(
      id=userId1, 
      name="Stefan", 
      surname="Stefan", 
      age=99, 
      personalId="12312312312", 
      citizenship="PL", 
      email="stefan@stefan.com"
    )
    usr2 = User(
      id=userId2, 
      name="Stefan", 
      surname="Stefan", 
      age=99, 
      personalId="12312312312", 
      citizenship="PL", 
      email="stefan@stefan.com"
    )
    usr3 = User(
      id=userId3, 
      name="Stefan", 
      surname="Stefan", 
      age=99, 
      personalId="12312312312", 
      citizenship="PL", 
      email="stefan@stefan.com"
    )

    print("[!!] Testing the application. Correct scenarios: ")

    # Adding three users to the database
    test_add_user(usr1)
    test_add_user(usr2)
    test_add_user(usr3)
    
    # Test getting list of users
    test_get_list_of_users(3)

    # Get first user
    test_get_specific_user(userId1)

    # Modify first user
    newName = 'Ryszard'
    usr1.name = newName
    usr1.surname = newName
    test_modify_specific_user(usr1, userId1, newName=newName)

    # Delete first user
    test_delete_specific_user(userId1)
    test_get_list_of_users(2)

    # Incorrect scenarios
    print("[!!] Testing the application. Incorrect scenarios: ")
    
    # Add if user already exists
    test_add_user_already_exists(usr2)

    # Request user that does not exist
    test_get_user_does_not_exist(userId1)

    # Modify user that does not exist
    test_modify_user_does_not_exist(usr1, userId1)

    # Delete user that does not exist
    test_delete_user_that_does_not_exist(userId1)

def test_basic_auth(username, password):
    headers = {
        'Authorization' : 'Basic ' + b64encode((username + ':' + password).encode()).decode()
    }
    response = client.get("/users", params=dict(requestId=str(uuid4()), sendDate=datetime.now().isoformat()), headers=headers)
    
    print("[*](Correct credentials) Getting list of users returned: ", response.status_code)
    assert response.status_code == 200

    dummypassword = 'dummypassword'
    headers = {
        'Authorization' : 'Basic ' + b64encode((username + ':' + dummypassword).encode()).decode()
    }
    response = client.get("/users", params=dict(requestId=str(uuid4()), sendDate=datetime.now().isoformat()), headers=headers)
    print("[*](Incorrect credentials) Getting list of users returned: ", response.status_code, response.text)

def test_oauth(username, password):
    body = {
        'username' : username,
        'password' : password
    }

    response = client.post("/token", data=body)

    assert response.status_code == 200
    print("[*]() Getting token: ", response.status_code)

    # return JWT token as text
    return 'Bearer ' + loads(response.text)['access_token']
#

def test_oauth_external():
    creds = loads(open('tokensecret.json', 'r').read())
    creds = creds['username'] + ':' + creds['password']
    headers = {
        'Authorization' : 'Basic ' + b64encode(creds.encode()).decode()
    }

    response = request(
        'POST',
        'https://pba-auth-server.herokuapp.com/oauth/token',
        data={"grant_type":"client_credentials"}, 
        headers=headers
    )

    assert response.status_code == 200
    print("[*]() Getting token: ", response.status_code)
    return loads(response.text)['access_token']
#

def test_add_user_auth(token, user, expected_response=200):
    requestHeader=dict(requestId=str(uuid4()), sendDate=str(datetime.now().isoformat()))
    
    response = client.post(
                "/users", 
                headers={'Content-Type' : 'application/json', 'Authorization' : token},
                json=dict(requestHeader=requestHeader, user=jsonable_encoder(user)),
    )
    print("[*] Adding user returned: ", response.status_code, " response text: ", response.text)
    assert response.status_code == expected_response

def test_api_auth():
    #test_basic_auth('sp12345', '12345')
    #exit()
    
    # Test data
    userId1 = '12345675-1234-5678-1234-567812345678'
    usr1 = User(
      id=userId1, 
      name="Stefan", 
      surname="Stefan", 
      age=99, 
      personalId="12312312312", 
      citizenship="PL", 
      email="stefan@stefan.com"
    )
    usr2 = usr1.copy()
    usr2.id = '12345675-1234-5678-1234-567812345111'

    # Get token
    token = test_oauth('sp12345', '12345')
    # Add user - ok
    test_add_user_auth(token, usr1, expected_response=200)
    sleep(30)
    print("[*] 30 seconds passed.")
    # After token expiry - response should be unauthorized
    test_add_user_auth(token, usr2, expected_response=401)

# Signature tests - lab6
def test_signature_integrity_hmac():

    # Create test user and auth data
    token = test_oauth('sp12345', '12345')
    xjwssig_pass = 'secret123456'
    newUserId= str(uuid4())
    usr1 = User(
      id=newUserId, 
      name="Stefan", 
      surname="Stefan", 
      age=99, 
      personalId="12312312312", 
      citizenship="PL", 
      email="stefan@stefan.com"
    )
    
    # Send request to create user
    rh  =dict(requestId=str(uuid4()), sendDate=str(datetime.now().isoformat()))
    requestBody    = dict(requestHeader=rh, user=jsonable_encoder(usr1))
    hmacSig = hmac.new(xjwssig_pass.encode(), str(requestBody).encode(), digestmod=sha256)
    
    requestHeaders = {'Content-Type' : 'application/json', 
                      'Authorization' : token,
                      'X-HMAC-SIGNATURE' : hmacSig.hexdigest()}
    
    response = client.post(
                "/users", 
                headers=requestHeaders,
                json=requestBody,

    )
    
    print("[*] HMAC Verified. User added successfully. Code: ", response.status_code)
    assert response.status_code == 200

    # Send request to create user
    rh  =dict(requestId=str(uuid4()), sendDate=str(datetime.now().isoformat()))
    requestBody    = dict(requestHeader=rh, user=jsonable_encoder(usr1))
    hmacSig = hmac.new(xjwssig_pass.encode(), str(requestBody).encode(), digestmod=sha256)
    # Modifying the signature to receive verification error
    modifiedSig = hmacSig.hexdigest().replace('A', 'E').replace('1', '5').replace('3', '9')
    
    requestHeaders = {'Content-Type' : 'application/json', 
                      'Authorization' : token,
                      'X-HMAC-SIGNATURE' : modifiedSig}
    
    response = client.post(
                "/users", 
                headers=requestHeaders,
                json=requestBody,

    )

    print("[*] Sending modified signature (HMAC). Should receive verification error Code: ", response.status_code, ' Response: ', response.text)
    assert response.status_code == 422
    
    
    # Send request to modify user
    # Patch user
    rh  = dict(requestId=str(uuid4()), sendDate=str(datetime.now().isoformat()))
    requestBody  = requestBody    = dict(requestHeader=rh, user=jsonable_encoder(usr1))
    signed = jws.sign(requestBody, xjwssig_pass, algorithm='HS256')
    requestHeaders = {'Content-Type' : 'application/json', 
                      'Authorization' : token,
                      'X-JWS-SIGNATURE' : signed}

    response = client.put(
                f"/users/{newUserId}", 
                headers=requestHeaders,
                json=requestBody
    )
    print("[*] JWS Verified. User modified successfully. Code: ", response.status_code)
    assert response.status_code == 200
    #

    # Send request to modify user
    # Patch user
    rh  = dict(requestId=str(uuid4()), sendDate=str(datetime.now().isoformat()))
    requestBody  = requestBody    = dict(requestHeader=rh, user=jsonable_encoder(usr1))
    signed = jws.sign(requestBody, xjwssig_pass, algorithm='HS256')
    # Modifying valid signature to simulate veirifcation error
    signed_modified = signed.replace('a', 'e').replace('1', '3').replace('b', 'c').replace('p', 'u')
    requestHeaders = {'Content-Type' : 'application/json', 
                      'Authorization' : token,
                      'X-JWS-SIGNATURE' : signed_modified}

    response = client.put(
                f"/users/{newUserId}", 
                headers=requestHeaders,
                json=requestBody
    )
    print("[*] Sending modified singature (JWS). Should receive verification error. Code: ", response.status_code)
    assert response.status_code == 422
    #
#
    




if __name__ == "__main__":
    # test_api()        <= lab4
    # test_api_auth()   <= lab5
    test_signature_integrity_hmac()


