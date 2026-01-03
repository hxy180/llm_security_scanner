def login(username):
    sql = "SELECT * FROM users WHERE name = '" + username + "'"
    db.execute(sql)
