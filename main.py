from __future__ import annotations
from uuid import UUID
from fastapi.encoders import jsonable_encoder
from fastapi import FastAPI, Response, status, HTTPException, Depends, Header
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordBearer,\
 OAuth2PasswordRequestForm
import secrets
from passlib.hash import bcrypt
from passlib.context import CryptContext
from jose import JWTError, jwt, jws
from jose.exceptions import ExpiredSignatureError, JWSError
from models import UserListResponse, UserResponse, User, Stub, RequestHeader,\
    CreateRequest, ResponseHeader, UpdateRequest,\
    SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, Token, INTERNAL, EXTERNAL,\
         TOKEN_GENERATION, CredentialsException, ExpiryException, ScopeException, Error,\
             CredentialsExceptionBasic, UnicornException
from db import RunTimeDB, Errors
from datetime import datetime, timedelta
from json import loads, dumps
from requests import request
from base64 import b64encode
from fastapi.responses import JSONResponse
import hmac 
import hashlib
from hashlib import sha256

usr_db = RunTimeDB()
usr1 = User(id='12345678-1234-5678-1234-567812345678', name="Stefan", surname="Stefan", age=99, personalId="12312312312", citizenship="PL", email="stefan@stefan.com")
usr2 = User(id='22345678-1234-5678-1234-567812345678', name="Stefan", surname="Stefan", age=99, personalId="12312312312", citizenship="PL", email="stefan@stefan.com")
usr3 = User(id='32345678-1234-5678-1234-567812345678', name="Stefan", surname="Stefan", age=99, personalId="12312312312", citizenship="PL", email="stefan@stefan.com")
usr_db.addUser(usr1)
usr_db.addUser(usr2)
usr_db.addUser(usr3)
#

app = FastAPI(
    title='Users CRUD interface',
    description='Specification of the CRUD interface',
    version='1.0.0',
    debug=True
)
security = HTTPBasic()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")
# json file with two fields - username and password,
# giving access to external token generation service
tokensecretfile = 'tokensecret.json'
external_token_url = 'https://pba-auth-server.herokuapp.com/oauth/token'
xjwssig_pass = 'secret123456'

"""
    Exception handling
"""
@app.exception_handler(UnicornException)
async def unicorn_exception_handler(request: Request, exc: UnicornException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "responseHeader" : {
                'requestId' : exc.requestId,
                'sendDate' : exc.sendDate
            },
            "code" : exc.code,
            "message": exc.message
        },
    )

"""
    Security : HttpBasicAuth
"""
def authenticate_user(username: str, password: str):
    user_dict = usr_db.getCredentials()
    if not user_dict:
        return False
    
    if  bcrypt.verify(password ,user_dict['password']) and username == user_dict['username']:
        return True
    return False
#

def http_basic_auth(credentials: HTTPBasicCredentials = Depends(security)):
    auth_status = authenticate_user(credentials.username, credentials.password)
    if not auth_status:
        raise CredentialsExceptionBasic
    return credentials.username
#

"""
    Security : OAuth
"""
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def oauth_auth(token: str = Depends(oauth2_scheme)):
    # Get client public key
    if TOKEN_GENERATION == EXTERNAL:
        public_key = open('clientkey.pub').read()
    else:
        public_key = SECRET_KEY

    # Decode token and validate it
    try:
        payload = jwt.decode(token, public_key, algorithms=[ALGORITHM])
        username: str = payload.get("client_id")
        scope: list = payload.get("scope")[0]

        if username != 'pba_user':
            raise CredentialsException
        if scope != 'pba_resource':
            raise ScopeException
    except JWTError:
        raise CredentialsException
    except ExpiredSignatureError:
        raise ExpiryException
    
    return True
#

"""
    Integrity : HMAC and JWS
"""
def verify_jws(X_JWS_SIGNATURE:str):
    try: 
        jws.verify(X_JWS_SIGNATURE, xjwssig_pass, algorithms=['HS256'])
    except JWSError:
        return False
    return True
#

def verify_hmac(X_HMAC_SIGNATURE:str, request):
    raw_request = str(jsonable_encoder(request))
    generated_sig = hmac.new(
            xjwssig_pass.encode(), 
            raw_request.encode(), 
            digestmod=sha256).hexdigest()

    if hmac.compare_digest(X_HMAC_SIGNATURE, generated_sig):
        return True
    return False
#


"""
    ================== ENDPOINTS ====================
"""


"""
    Get list of all users
"""
@app.get('/users', response_model=UserListResponse)
async def get_all_users(requestId : UUID, sendDate : datetime, username: str = Depends(http_basic_auth)) -> UserListResponse:
    return UserListResponse(responseHeader=ResponseHeader(requestId=requestId, sendDate=sendDate), usersList=usr_db.getList())
#

"""
    Create user
"""
@app.post('/users', response_model=UserResponse)
async def create_user(request : CreateRequest, X_HMAC_SIGNATURE: str = Header(None), form_data: OAuth2PasswordBearer = Depends(oauth_auth)) -> UserResponse:
    # Verify that the request has not been tampered with
    if not verify_hmac(X_HMAC_SIGNATURE, request):
        raise UnicornException(
            code="INTEGRITY_ERROR",
            message="Could not verify integrity of the request",
            requestId=str(request.requestHeader.requestId), 
            sendDate=str(request.requestHeader.sendDate), 
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY
        )

    # If user does not exist, and given request is correct - create user and return it
    if usr_db.addUser(request.user) == Errors.action_completed_ok:
        return UserResponse(responseHeader=request.requestHeader, user=request.user)
    # If user already exists in the database
    elif usr_db.addUser(request.user) == Errors.error_user_exists:
        raise UnicornException(
            code="USER_ALREADY_EXISTS",
            message="Resource doesn't exist",
            requestId=str(request.requestHeader.requestId), 
            sendDate=str(request.requestHeader.sendDate), 
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY
        )
#   

"""
    Get user
"""
@app.get('/users/{id}', response_model=UserResponse)
async def get_user_by_id(requestId : UUID, sendDate : datetime, id : UUID, username: str = Depends(http_basic_auth)) -> UserResponse:
    user = usr_db.getUser(id)
    # User was not found in the database
    if user == Errors.error_user_does_not_exist:
        raise UnicornException(
            code="NOT_FOUND",
            message="Resource doesn't exist",
            requestId=str(requestId), 
            sendDate=str(sendDate), 
            status_code=status.HTTP_404_NOT_FOUND
        )
    # User found in database, return it
    else:
        rp = ResponseHeader(requestId=requestId, sendDate=sendDate)
        return UserResponse(responseHeader=rp, user=user)
#

"""
    Update user
"""
@app.put('/users/{id}', response_model=UserResponse)
async def update_user(updateRequest : UpdateRequest, id : UUID, X_JWS_SIGNATURE: str = Header(None), form_data: OAuth2PasswordBearer = Depends(oauth_auth)) -> UserResponse:    
    # Verify that request has not been tampered with
    if not verify_jws(X_JWS_SIGNATURE):
        raise UnicornException(
            code="INTEGRITY_ERROR",
            message="Could not verify integrity of the request",
            requestId=str(updateRequest.requestHeader.requestId), 
            sendDate=str(updateRequest.requestHeader.sendDate), 
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY
        )
    
    # id given in the path and sent in user object must be the same. Otherwise, return error
    if id == updateRequest.user.id:
        user = usr_db.modifyUser(updateRequest.user) 
        if user == Errors.error_user_does_not_exist:
            raise UnicornException(
            code="NOT_FOUND",
            message="Resource doesn't exist",
            requestId=str(updateRequest.requestHeader.requestId), 
            sendDate=str(updateRequest.requestHeader.sendDate), 
            status_code=status.HTTP_404_NOT_FOUND
        )
        return UserResponse(responseHeader=updateRequest.requestHeader, user=usr_db.modifyUser(updateRequest.user))
    else:
        raise UnicornException(
            code="DIFFERENT_ID_IN_PATH_AND_USER",
            message="Resource doesn't exist",
            requestId=str(updateRequest.requestHeader.requestId), 
            sendDate=str(updateRequest.requestHeader.sendDate), 
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY
        )
#

"""
    Delete user
"""
@app.delete('/users/{id}', response_model=None)
async def delete_user(requestId : UUID, sendDate : datetime, id : UUID, form_data: OAuth2PasswordRequestForm = Depends()) -> None:
    delstatus = usr_db.deleteUser(id)
    # If user does not exist, raise error
    if delstatus == Errors.error_user_does_not_exist:
        raise UnicornException(
            code="NOT_FOUND",
            message="Resource doesn't exist",
            requestId=str(requestId), 
            sendDate=str(sendDate), 
            status_code=status.HTTP_404_NOT_FOUND
        )
    # Otherwise return OK
    else:
        return None
#

"""
    OAuth - get access token
"""
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()) -> Token:
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise CredentialsException
    
    # Contact external server for the token
    if TOKEN_GENERATION == EXTERNAL:
        creds = loads(open(tokensecretfile).read())
        creds = creds['username'] + ':' + creds['password']
        headers = {
            'Authorization' : 'Basic ' + b64encode(creds.encode()).decode()
        }

        response = request(
            'POST',
            external_token_url,
            data={"grant_type":"client_credentials"}, 
            headers=headers
        )
        access_token = loads(response.text)['access_token']
    else:
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={
                "scope": ["pba_resource"],
                "jti": "LeDhcmLv9bjijR0e-O5T4HE4-3A",
                "client_id": "pba_user"
            }, 
            expires_delta=access_token_expires
        )

    return {"access_token": access_token, "token_type": "bearer"}
#