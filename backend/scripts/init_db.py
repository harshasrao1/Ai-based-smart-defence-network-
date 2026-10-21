from defence.storage import connect, DEFAULT_DB
if __name__ == '__main__':
    connect().close()
    print(f'Database ready: {DEFAULT_DB}')
