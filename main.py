from __future__ import annotations
from uuid import UUID
from fastapi import FastAPI, Response, status, HTTPException, Depends
from fastapi.logger import logger
import logging
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordBearer, OAuth2PasswordRequestForm
import secrets
from passlib.hash import bcrypt
from passlib.context import CryptContext
from jose import JWTError, jwt
from models import UserListResponse, UserResponse, User, Stub, RequestHeader,\
    CreateRequest, ResponseHeader, UpdateRequest,\
    SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, Token
from db import RunTimeDB, Errors
from datetime import datetime, timedelta

#if __name__ == '__main__':
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
)
security = HTTPBasic()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

"""
    Logging facility
"""
gunicorn_logger = logging.getLogger('gunicorn.error')
logger.handlers = gunicorn_logger.handlers
if __name__ != "main":
    logger.setLevel(gunicorn_logger.level)
else:
    logger.setLevel(logging.DEBUG)

"""
    Security : HttpBasicAuth
"""
def authenticate_user(username: str, password: str):
    user_dict = usr_db.getCredentials()
    return True
    #if not user_dict:
    #    return False
    
    if not bcrypt.using(rounds=13).hash(password) == user_dict['password'] and\
            not username == user_dict['username']:
        return True
    return False
#

def http_basic_auth(credentials: HTTPBasicCredentials = Depends(security)):
    auth_status = authenticate_user(credentials.username, credentials.password)
    if not auth_status:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
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
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    #Auth completed
    return True
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
# TODO - change here
@app.post('/users', response_model=UserResponse)
async def create_user(request : CreateRequest, form_data: OAuth2PasswordBearer = Depends(oauth_auth)) -> UserResponse:
    # If user does not exist, and given request is correct - create user and return it
    if usr_db.addUser(request.user) == Errors.action_completed_ok:
        return UserResponse(responseHeader=request.requestHeader, user=request.user)
    # If user already exists in the database
    elif usr_db.addUser(request.user) == Errors.error_user_exists:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Unprocessable entity. Codes: USER_ALREADY_EXISTS")
#   

"""
    Get user
"""
@app.get('/users/{id}', response_model=UserResponse)
async def get_user_by_id(requestId : UUID, sendDate : datetime, id : UUID, username: str = Depends(http_basic_auth)) -> UserResponse:
    user = usr_db.getUser(id)
    # User was not found in the database
    if user == Errors.error_user_does_not_exist:
       raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Unprocessable entity. Codes: USER_DOES_NOT_EXIST")
    # User found in database, return it
    else:
        rp = ResponseHeader(requestId=requestId, sendDate=sendDate)
        return UserResponse(responseHeader=rp, user=user)
#

"""
    Update user
"""
@app.put('/users/{id}', response_model=UserResponse)
async def update_user(updateRequest : UpdateRequest, id : UUID, form_data: OAuth2PasswordRequestForm = Depends()) -> UserResponse:
    # id given in the path and sent in user object must be the same. Otherwise, return error
    if id == updateRequest.user.id:
        user = usr_db.modifyUser(updateRequest.user) 
        if user == Errors.error_user_does_not_exist:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Unprocessable entity. Codes: USER_DOES_NOT_EXIST")
        return UserResponse(responseHeader=updateRequest.requestHeader, user=usr_db.modifyUser(updateRequest.user))
    else:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Unprocessable entity. Codes: DIFFERENT_ID_IN_PATH_AND_USER")
#

"""
    Delete user
"""
@app.delete('/users/{id}', response_model=None)
async def delete_user(requestId : UUID, sendDate : datetime, id : UUID, form_data: OAuth2PasswordRequestForm = Depends()) -> None:
    delstatus = usr_db.deleteUser(id)
    # If user does not exist, raise error
    if delstatus == Errors.error_user_does_not_exist:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Unprocessable entity. Codes: USER_DOES_NOT_EXIST")
    # Otherwise return OK
    else:
        return None
#

"""
    OAuth - get access token
"""
# TODO: ofc change here
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()) -> Token:
    # Stuck here - I cannot pass creds to this endpoint, giving username and password fails
    logger.info("123")
    user = authenticate_user(form_data.username, form_data.password) # pass just form_data here? 
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}
#