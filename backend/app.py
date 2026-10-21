"""Flask API + same-origin frontend. Start with python app.py from backend/."""
import atexit
import hmac
from io import BytesIO
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import uuid
import pandas as pd
from flask import Flask, jsonify, request, session, send_from_directory, Response
from werkzeug.exceptions import HTTPException
from defence import auth
from defence.data import read_records, validate_features, missing_summary, targets, ValidationError
from defence.model import ROOT, train, load_bundle, predict, importance
from defence.model import unknown_categories
from defence.schema import FEATURES, CATEGORICAL, RATES, BINARY_FLAGS, CLASSES
from defence.storage import history, summary, save_predictions, network_history, network_counts
from defence.capture import PacketMonitor, interfaces
from defence.rules import simulation_packets

FRONTEND = ROOT.parent / 'frontend'

def json_records(frame):
    return json.loads(frame.to_json(orient='records'))


def create_app(test_config=None):
    app = Flask(__name__, static_folder=None)
    if test_config and test_config.get('SECRET_KEY'):
        key = test_config['SECRET_KEY']
    else:
        key = os.environ.get('SMART_DEFENCE_SECRET')
        if not key:
            try:
                secret_file = ROOT/'data'/'flask_secret.key'
                secret_file.parent.mkdir(exist_ok=True)
                try:
                    descriptor = os.open(secret_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    with os.fdopen(descriptor, 'w') as stream:
                        stream.write(secrets.token_hex(32))
                except FileExistsError:
                    pass
                key = secret_file.read_text().strip()
            except (OSError, PermissionError):
                tmp_secret = Path('/tmp') / 'flask_secret.key'
                try:
                    if tmp_secret.exists():
                        key = tmp_secret.read_text().strip()
                    else:
                        key = secrets.token_hex(32)
                        tmp_secret.write_text(key)
                except Exception:
                    key = secrets.token_hex(32)
            if not key or len(key) < 32:
                key = secrets.token_hex(32)
    is_secure = bool(os.environ.get('VERCEL') or os.environ.get('HTTPS'))
    app.config.update(SECRET_KEY=key, MAX_CONTENT_LENGTH=100*1024*1024,
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
                      SESSION_COOKIE_SECURE=is_secure, SESSION_COOKIE_NAME='smart_defence_session')
    if test_config:
        app.config.update(test_config)
    monitor = PacketMonitor(persist=True)
    app.extensions['monitor'] = monitor
    capture_lock, training_lock = threading.Lock(), threading.Lock()
    atexit.register(monitor.stop)

    def token():
        return session.get('auth_token')

    def payload():
        value = request.get_json(silent=True) or {}
        if not isinstance(value, dict):
            raise ValidationError('Expected a JSON object.')
        return value

    @app.before_request
    def access_control():
        if not request.path.startswith('/api/'):
            return
        session.setdefault('csrf', secrets.token_urlsafe(32))
        public = {'/api/session', '/api/setup', '/api/login', '/api/health'}
        if request.path not in public:
            user = auth.session_user(token(), touch=request.headers.get('X-Background-Poll') != '1')
            if not user:
                return jsonify(error='Sign in to access the dashboard.'), 401
        if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
            supplied = request.headers.get('X-CSRF-Token', '')
            if not hmac.compare_digest(supplied, session['csrf']):
                return jsonify(error='Session verification failed. Reload the page and try again.'), 403

    @app.after_request
    def secure_response(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        if request.path.startswith('/api/'):
            response.headers['Cache-Control'] = 'no-store'
        return response

    @app.errorhandler(Exception)
    def handle_error(exc):
        if isinstance(exc, HTTPException):
            return jsonify(error=exc.description), exc.code
        if isinstance(exc, auth.AuthError):
            return jsonify(error=str(exc)), 400
        if isinstance(exc, (ValidationError, ValueError, KeyError)):
            return jsonify(error=str(exc)), 400
        if isinstance(exc, (sqlite3.Error, OSError)):
            app.logger.error('Local resource error: %s', exc)
            return jsonify(error='Local storage or file access failed. Check the backend terminal and permissions.'), 503
        app.logger.exception('Request failed')
        return jsonify(error='The backend could not complete the request. Check its terminal for details.'), 500

    @app.get('/')
    def index():
        return send_from_directory(FRONTEND, 'index.html')

    @app.get('/assets/<path:name>')
    def assets(name):
        if name not in {'app.js', 'styles.css', 'logo.svg', 'favicon.ico', 'favicon.png', 'favicon-32x32.png'}:
            return jsonify(error='Asset not found.'), 404
        return send_from_directory(FRONTEND, name)

    @app.get('/favicon.ico')
    def favicon():
        return send_from_directory(FRONTEND, 'favicon.ico', mimetype='image/x-icon')

    @app.get('/api/health')
    def health():
        return jsonify(status='ok')

    @app.get('/api/session')
    def auth_state():
        return jsonify(configured=auth.is_configured(), username=auth.session_user(token(), touch=False), csrf=session['csrf'])

    @app.post('/api/setup')
    def setup():
        values = payload()
        if values.get('password') != values.get('confirm_password'):
            raise auth.AuthError('Passwords do not match.')
        auth.setup_admin(str(values.get('username', '')), values.get('password', ''))
        return jsonify(message='Administrator created. Sign in with your new credentials.'), 201

    @app.post('/api/login')
    def sign_in():
        values = payload()
        result = auth.login(str(values.get('username', '')), values.get('password', ''))
        session.clear()
        session.update(auth_token=result, csrf=secrets.token_urlsafe(32))
        return jsonify(username=auth.session_user(result), csrf=session['csrf'])

    @app.post('/api/logout')
    def sign_out():
        auth.logout(token())
        monitor.stop()
        session.clear()
        return jsonify(message='Signed out.')

    @app.post('/api/password')
    def password_change():
        values = payload()
        if values.get('new_password') != values.get('confirm_password'):
            raise auth.AuthError('New passwords do not match.')
        auth.change_password(token(), values.get('current_password', ''), values.get('new_password', ''))
        monitor.stop()
        session.clear()
        return jsonify(message='Password updated. Sign in again.')

    @app.get('/api/schema')
    def schema():
        sample = read_records(ROOT/'samples'/'nsl_kdd_prediction_sample.csv').iloc[0].to_dict()
        return jsonify(features=FEATURES, categorical=CATEGORICAL, rates=RATES, binary_flags=BINARY_FLAGS, defaults=sample)

    @app.get('/api/overview')
    def overview():
        total, normal, attack, distribution = summary()
        try:
            meta = load_bundle()['metadata']
            model = {'ready': True, 'train_records': meta['train_records'], 'test_records': meta['test_records'],
                     'created_at': meta['created_at'], 'accuracy': meta['binary']['accuracy'], 'model_id': meta['model_id']}
        except ValidationError as exc:
            model = {'ready': False, 'message': str(exc)}
        return jsonify(total=total, normal=normal, attack=attack, distribution=json_records(distribution),
                       network=network_counts(), recent_predictions=json_records(history(status='Attack',limit=5)),
                       recent_rules=json_records(network_history(kind='alerts',mode='Live',limit=5)), model=model)

    @app.post('/api/dataset')
    def dataset():
        source = request.files.get('file')
        if source is None:
            raise ValidationError('Choose a dataset file first.')
        data = read_records(source)
        classes = {}
        if 'label' in data:
            source.seek(0)
            labeled = read_records(source,True)
            classes = targets(labeled)[1].value_counts().to_dict()
        stats = validate_features(data).describe().T.reset_index().rename(columns={'index':'feature'})
        missing = missing_summary(data).reset_index().rename(columns={'index':'feature'})
        return jsonify(records=len(data), preview=json_records(data.head(100)), missing=json_records(missing), statistics=json_records(stats), classes=classes)

    @app.get('/api/model')
    def model_status():
        bundle = load_bundle()
        return jsonify(metrics=bundle['metadata'], importance=json_records(importance(bundle).head(15)))

    @app.post('/api/train')
    def train_model():
        if not training_lock.acquire(blocking=False):
            return jsonify(error='Training is already in progress.'), 409
        try:
            source = request.form.get('source','included')
            if source == 'uploads':
                training, testing = request.files.get('train'), request.files.get('test')
                if training is None or testing is None:
                    raise ValidationError('Upload both training and testing files.')
                # FileStorage.name refers to its form field; BytesIO.name preserves provenance.
                a,b=BytesIO(training.read()),BytesIO(testing.read())
                a.name,b.name=Path(training.filename).name,Path(testing.filename).name
            elif source == 'synthetic':
                a,b=ROOT/'samples'/'synthetic_train.csv',ROOT/'samples'/'synthetic_test.csv'
            elif source == 'included':
                a,b=ROOT/'data'/'KDDTrain+.txt',ROOT/'data'/'KDDTest+.txt'
            else:
                raise ValidationError('Invalid training source.')
            bundle=train(a,b,trees=int(request.form.get('trees',150)))
            return jsonify(metrics=bundle['metadata'])
        finally:
            training_lock.release()

    @app.post('/api/predict')
    def prediction():
        source=request.files.get('file')
        if source is not None:
            data=read_records(source)
            name=Path(source.filename or 'Uploaded CSV').name
        else:
            values=payload()
            if values.get('sample'):
                data=read_records(ROOT/'samples'/'nsl_kdd_prediction_sample.csv');name='Included NSL-KDD sample'
            elif isinstance(values.get('record'),dict):
                data=pd.DataFrame([values['record']]);name='Manual entry'
            else:
                raise ValidationError('Supply a file, record, or sample request.')
        bundle=load_bundle()
        warnings=unknown_categories(bundle,data)
        result=predict(bundle,data)
        save_predictions(result,data,str(uuid.uuid4()),name)
        return jsonify(count=len(result), results=json_records(result.head(500)), shown=min(len(result),500), warnings=warnings,
                       message='All results saved. Export complete predictions from Alert History.')

    def selected_history():
        kind=request.args.get('kind','predictions')
        if kind=='predictions':
            return history(status=request.args.get('status','All'),category=request.args.get('category','All'),search=request.args.get('search',''))
        if kind in {'events','alerts'}:
            return network_history(kind=kind,mode=request.args.get('mode','All'),attack_type=request.args.get('attack_type','All'),search=request.args.get('search',''))
        raise ValidationError('Unknown history type.')

    @app.get('/api/history')
    def history_api():
        frame=selected_history()
        page=max(1,int(request.args.get('page',1)))
        return jsonify(total=len(frame),page=page,records=json_records(frame.iloc[(page-1)*100:page*100]))

    @app.get('/api/history/export')
    def history_export():
        frame=selected_history().copy()
        for col in frame.select_dtypes(include=['object','string']):
            frame[col]=frame[col].map(lambda value: "'"+value if isinstance(value,str) and value.startswith(('=','+','-','@')) else value)
        return Response(frame.to_csv(index=False),mimetype='text/csv',headers={'Content-Disposition':'attachment; filename="history_export.csv"'})

    @app.get('/api/sample')
    def sample_download():
        return send_from_directory(ROOT/'samples','nsl_kdd_prediction_sample.csv',as_attachment=True)

    @app.post('/api/simulate')
    def simulate():
        scenario=payload().get('scenario')
        if scenario not in {'Port Scan','High Traffic Rate','Normal Traffic'}:
            raise ValidationError('Choose a supported scenario.')
        simulator=PacketMonitor(persist=True)
        for record in simulation_packets(scenario):
            simulator.ingest(record,record['simulation_offset'],mode='Simulation')
        if simulator.error:
            raise OSError(simulator.error)
        return jsonify(scenario=scenario,events=simulator.snapshot(),alerts=simulator.alert_snapshot())

    @app.get('/api/interfaces')
    def available_interfaces():
        try:
            return jsonify(interfaces=interfaces())
        except Exception as exc:
            return jsonify(interfaces=[],warning=f'Capture is unavailable: {exc}. Install Npcap on Windows or use Simulation Mode.')

    @app.get('/api/capture')
    def capture_status():
        return jsonify(running=monitor.running,count=monitor.count,error=monitor.error,
                       events=monitor.snapshot(),alerts=monitor.alert_snapshot(),evicted_sources=monitor.detector.evicted_sources)

    @app.post('/api/capture/start')
    def capture_start():
        values=payload()
        if values.get('authorized') is not True:
            raise ValidationError('Confirm authorization before capturing traffic.')
        interface=values.get('interface')
        duration=int(values.get('duration',60))
        if not 10<=duration<=120:
            raise ValidationError('Capture duration must be 10–120 seconds.')
        with capture_lock:
            if monitor.running:
                return jsonify(error='Capture is already running.'),409
            try:
                available = [i['id'] if isinstance(i, dict) else i for i in interfaces()]
                if interface not in available:
                    raise ValidationError('Select an available interface.')
                monitor.start(interface,duration)
            except ValidationError:
                raise
            except Exception as exc:
                return jsonify(error=f'Capture could not start: {exc}. Check Npcap/permissions or use simulation.'),400
        return jsonify(message='Capture requested. Check live status for asynchronous setup errors.')

    @app.post('/api/capture/stop')
    def capture_stop():
        with capture_lock:
            monitor.stop()
        return jsonify(message='Capture stopped.')

    return app

if __name__=='__main__':
    create_app().run(host='127.0.0.1',port=5000,debug=False,threaded=True)
