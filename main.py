from __future__ import annotations
from uuid import UUID
from fastapi import FastAPI, Response, status, HTTPException
from models import UserListResponse, UserResponse, User, Stub, RequestHeader, CreateRequest, ResponseHeader, UpdateRequest
from db import RunTimeDB, Errors
from datetime import datetime

#if __name__ == '__main__':
usr_db = RunTimeDB()
#usr1 = User(id='12345678-1234-5678-1234-567812345678', name="Stefan", surname="Stefan", age=99, personalId="12312312312", citizenship="PL", email="stefan@stefan.com")
#usr2 = User(id='22345678-1234-5678-1234-567812345678', name="Stefan", surname="Stefan", age=99, personalId="12312312312", citizenship="PL", email="stefan@stefan.com")
#usr3 = User(id='32345678-1234-5678-1234-567812345678', name="Stefan", surname="Stefan", age=99, personalId="12312312312", citizenship="PL", email="stefan@stefan.com")
#usr_db.addUser(usr1)
#usr_db.addUser(usr2)
#usr_db.addUser(usr3)
#

app = FastAPI(
    title='Users CRUD interface',
    description='Specification of the CRUD interface',
    version='1.0.0',
)

"""
    Get list of all users
"""
@app.get('/users', response_model=UserListResponse)
async def get_all_users(requestId : UUID, sendDate : datetime) -> UserListResponse:
    return UserListResponse(responseHeader=ResponseHeader(requestId=requestId, sendDate=sendDate), usersList=usr_db.getList())
#

"""
    Create user
"""
@app.post('/users', response_model=UserResponse)
async def create_user(request : CreateRequest) -> UserResponse:
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
async def get_user_by_id(requestId : UUID, sendDate : datetime, id : UUID) -> UserResponse:
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
# Should the app allow changing UUID of user? It should not i guess
@app.put('/users/{id}', response_model=UserResponse)
async def update_user(updateRequest : UpdateRequest, id : UUID) -> UserResponse:
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
async def delete_user(requestId : UUID, sendDate : datetime, id : UUID) -> None:
    delstatus = usr_db.deleteUser(id)
    # If user does not exist, raise error
    if delstatus == Errors.error_user_does_not_exist:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Unprocessable entity. Codes: USER_DOES_NOT_EXIST")
    # Otherwise return OK
    else:
        return None
#
