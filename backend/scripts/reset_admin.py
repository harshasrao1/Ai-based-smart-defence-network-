"""Local recovery: python -m scripts.reset_admin (interactive, no password arguments)."""
from getpass import getpass
from defence.auth import reset_password, AuthError

def main():
    username = input('Administrator username: ').strip()
    password = getpass('New password (at least 12 characters): ')
    confirmation = getpass('Confirm new password: ')
    if password != confirmation:
        raise AuthError('Passwords do not match.')
    reset_password(username, password)
    print('Administrator password reset. All existing sessions were revoked.')

if __name__ == '__main__':
    try:
        main()
    except (AuthError, OSError) as exc:
        raise SystemExit(str(exc))
