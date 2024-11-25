CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    security_key TEXT
);

CREATE TABLE IF NOT EXISTS possible_permissions (permission_name TEXT PRIMARY KEY, description TEXT, is_boolean BOOLEAN DEFAULT true);

CREATE TABLE IF NOT EXISTS user_permissions (
    username TEXT REFERENCES users (username) ON DELETE CASCADE,
    permission_name TEXT REFERENCES possible_permissions (permission_name) ON DELETE CASCADE,
    permission_value BOOLEAN,
    PRIMARY KEY (username, permission_name)
);

DELETE FROM possible_permissions *;

INSERT INTO possible_permissions (permission_name, description, is_boolean) VALUES
    (
        'admin',
        'grants full control, and control over other peoples permissions',
        false
    ),
    (
        'fs::read',
        'grants the user permission to read any non-admin requiring files',
        false
    ),
    (
        'fs::write',
        'grants the user permission to read any non-admin requiring files',
        false
    ),
    (
        'fs::mk_dir',
        'grants the user permission to make directories so long as it doesnt require admin permissions',
        false
    ),
    (
        'fs::rm',
        'grants the user permisssion to remove non-privilaged files',
        false
    ),
    (
        'input::key',
        'grants the user to cause keypresses and keyups',
        false
    ),
    (
        'input::mouse',
        'grants the user the ability to move the mouse',
        false
    ),
    (
        'input::mousebtn',
        'grants the user the ability to press mouse buttons',
        false
    ),
    (
        'execution::run_macro_script',
        'grants the user permission to run macro scripts',
        false
    ),
    (
        'execution::voicemeeter',
        'exposes the voicemeeter API for Javascript Contexts when this user uses a macro',
        false
    ),
    (
        'execution::obs' 'exposes the OBS API for Javascript Contexts when this user uses a macro' false
    ),
    (
        'integrations::obs',
        'allows this user to use the OBS integration for tiles',
        false
    ),
    (
        'integrations::voicemeeter',
        'allows this user to use the voicemeeter integration for tiles',
        false
    );
