UPDATE users
SET
    password_hash = ?1,
    salt = ?2,
    security_key = ?3
WHERE
    username = ?4
