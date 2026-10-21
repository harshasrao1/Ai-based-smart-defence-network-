from io import BytesIO
import json
from pathlib import Path
import pytest
from app import create_app

PASSWORD='API-Test-Passphrase-123'
ROOT=Path(__file__).resolve().parents[1]

@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.setenv('SMART_DEFENCE_AUTH_DB',str(tmp_path/'auth.sqlite3'))
    monkeypatch.setenv('SMART_DEFENCE_DB',str(tmp_path/'history.sqlite3'))
    app=create_app({'TESTING':True,'SECRET_KEY':'test-only-key-never-for-production'})
    return app.test_client()

def get_csrf(client):
    return client.get('/api/session').get_json()['csrf']

def post(client,url,data=None,csrf=None):
    return client.post(url,json=data or {},headers={'X-CSRF-Token':csrf or get_csrf(client)})

def sign_in(client):
    result=post(client,'/api/setup',{'username':'admin','password':PASSWORD,'confirm_password':PASSWORD})
    assert result.status_code==201
    result=post(client,'/api/login',{'username':'admin','password':PASSWORD})
    assert result.status_code==200
    return result.get_json()['csrf']


def test_frontend_health_login_gate_and_csrf(client):
    assert client.get('/').status_code==200
    assert b'/assets/app.js' in client.get('/').data
    assert client.get('/assets/app.js').status_code==200
    assert client.get('/assets/styles.css').status_code==200
    assert client.get('/assets/../backend/app.py').status_code==404
    assert client.get('/api/health').get_json()=={'status':'ok'}
    assert client.get('/api/overview').status_code==401
    assert client.get('/api/history/export').status_code==401
    assert client.post('/api/setup',json={}).status_code==403
    csrf=sign_in(client)
    assert client.get('/api/overview').status_code==200
    assert client.post('/api/simulate',json={'scenario':'Port Scan'},headers={'X-CSRF-Token':'wrong'}).status_code==403
    response=post(client,'/api/logout',csrf=csrf)
    assert response.status_code==200
    assert client.get('/api/overview').status_code==401


def test_rule_simulations_event_filters_and_exports(client):
    csrf=sign_in(client)
    for scenario,n in [('Port Scan',1),('High Traffic Rate',1),('Normal Traffic',0)]:
        response=post(client,'/api/simulate',{'scenario':scenario},csrf)
        assert response.status_code==200,response.get_json()
        assert len(response.get_json()['alerts'])==n
    overview=client.get('/api/overview').get_json()
    assert overview['network']['Simulation']=={'events':128,'alerts':2}
    assert overview['network']['Live']=={'events':0,'alerts':0}
    assert client.get('/api/history?kind=events').get_json()['total']==128
    alerts=client.get('/api/history?kind=alerts&mode=Simulation&attack_type=Port%20Scan').get_json()
    assert alerts['total']==1
    assert client.get('/api/history?kind=alerts&mode=Live').get_json()['total']==0
    assert client.get('/api/history/export?kind=alerts').status_code==200
    assert b'Port Scan' in client.get('/api/history/export?kind=alerts').data


def test_real_model_prediction_upload_schema_and_manual(client):
    csrf=sign_in(client)
    result=post(client,'/api/predict',{'sample':True},csrf)
    assert result.status_code==200,result.get_json()
    assert result.get_json()['count']==25
    assert len(result.get_json()['results'])==25
    assert client.get('/api/model').status_code==200
    schema=client.get('/api/schema').get_json()
    assert len(schema['features'])==41
    result=post(client,'/api/predict',{'record':schema['defaults']},csrf)
    assert result.status_code==200,result.get_json()
    assert result.get_json()['count']==1
    sample=(ROOT/'samples'/'nsl_kdd_prediction_sample.csv').read_bytes()
    result=client.post('/api/predict',data={'file':(BytesIO(sample),'sample.csv')},headers={'X-CSRF-Token':csrf})
    assert result.status_code==200,result.get_json()
    assert client.get('/api/history?kind=predictions').get_json()['total']==51
    result=post(client,'/api/predict',{'record':{'duration':2}},csrf)
    assert result.status_code==400
    assert 'Missing features' in result.get_json()['error']


def test_dataset_analysis_and_invalid_upload(client):
    csrf=sign_in(client)
    sample=(ROOT/'samples'/'synthetic_test.csv').read_bytes()
    result=client.post('/api/dataset',data={'file':(BytesIO(sample),'dataset.csv')},headers={'X-CSRF-Token':csrf})
    assert result.status_code==200,result.get_json()
    assert result.get_json()['records']==75
    assert len(result.get_json()['classes'])==5
    result=client.post('/api/dataset',data={'file':(BytesIO(b'bad,input'),'bad.csv')},headers={'X-CSRF-Token':csrf})
    assert result.status_code==400


def test_password_change_expiry_and_capture_authorization(client):
    csrf=sign_in(client)
    assert post(client,'/api/capture/start',{'authorized':False},csrf).status_code==400
    assert client.get('/api/interfaces').status_code==200
    assert client.get('/api/capture').status_code==200
    response=post(client,'/api/password',{'current_password':PASSWORD,'new_password':'Replacement-Passphrase-456','confirm_password':'Replacement-Passphrase-456'},csrf)
    assert response.status_code==200,response.get_json()
    assert client.get('/api/overview').status_code==401
    assert post(client,'/api/login',{'username':'admin','password':PASSWORD}).status_code==400
    assert post(client,'/api/login',{'username':'admin','password':'Replacement-Passphrase-456'}).status_code==200


def test_training_endpoint_with_temporary_model_directory(client,tmp_path,monkeypatch):
    # Train tiny fixtures to exercise the API; preserve the bundled NSL-KDD model.
    import app as api_module
    original=api_module.train
    def train_temporary(a,b,trees=10):
        return original(a,b,output_dir=tmp_path/'models',trees=trees)
    monkeypatch.setattr(api_module,'train',train_temporary)
    csrf=sign_in(client)
    response=client.post('/api/train',data={'source':'synthetic','trees':'10'},headers={'X-CSRF-Token':csrf})
    assert response.status_code==200,response.get_json()
    assert response.get_json()['metrics']['test_records']==75
