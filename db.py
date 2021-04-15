class Errors:
  action_completed_ok = 0x00
  error_user_exists = 0x1
  error_user_does_not_exist = 0x02

class RunTimeDB:
  def __init__(self):
    self.users = dict()
  #

  # Add user to the databse
  def addUser(self, user):
    # If user already exists, return error
    if user.id in self.users.keys():
      return Errors.error_user_exists
    else:
      self.users[user.id] = user
      return Errors.action_completed_ok
  #
  
  # Return list of all users
  def getList(self):
    return [self.users[key] for key in self.users.keys()]
  
  # Get specific user from databse, by its id
  def getUser(self, id):
    if id in self.users.keys():
      return self.users[id]
    else:
      return Errors.error_user_does_not_exist
  #

  # Modify existing user in the databse
  def modifyUser(self, user):
    if user.id in self.users.keys():
      self.users[user.id] = user
      return self.users[user.id]
    else:
      return Errors.error_user_does_not_exist
  #

  def deleteUser(self, id):
    # Should return something saying that user has been deleted
    if id in self.users.keys():
      del self.users[id]
      return Errors.action_completed_ok
    else:
      return Errors.error_user_does_not_exist
  #
