"""
Tests for the code scanning endpoint:
  POST /analyze
"""


BENIGN_CODE = """
def add(a, b):
    return a + b

result = add(1, 2)
print(result)
"""

SUSPICIOUS_CODE = """
import subprocess
import os

def run_cmd(user_input):
    subprocess.call(user_input, shell=True)
    os.system(user_input)
"""


class TestAnalyze:
    def test_benign_returns_200(self, client):
        resp = client.post('/analyze', json={'code': BENIGN_CODE})
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'malicious' in data
        assert 'risk_level' in data
        assert 'confidence' in data

    def test_suspicious_code_scanned(self, client):
        resp = client.post('/analyze', json={'code': SUSPICIOUS_CODE})
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'malicious' in data
        assert data['risk_level'] in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')

    def test_missing_code_field(self, client):
        resp = client.post('/analyze', json={})
        assert resp.status_code == 400

    def test_empty_code(self, client):
        resp = client.post('/analyze', json={'code': ''})
        assert resp.status_code == 400

    def test_code_too_long(self, client):
        resp = client.post('/analyze', json={'code': 'x = 1\n' * 10000})
        assert resp.status_code == 400

    def test_non_string_code_rejected(self, client):
        resp = client.post('/analyze', json={'code': 12345})
        assert resp.status_code == 400

    def test_response_has_language_field(self, client):
        resp = client.post('/analyze', json={'code': BENIGN_CODE})
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'language' in data

    def test_with_filename_hint(self, client):
        resp = client.post('/analyze', json={
            'code': BENIGN_CODE,
            'filename': 'main.py',
        })
        assert resp.status_code == 200

    def test_result_cache_hit(self, client):
        """Second identical request should return same result (cached)."""
        payload = {'code': 'print("hello world")'}
        r1 = client.post('/analyze', json=payload)
        r2 = client.post('/analyze', json=payload)
        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r1.get_json()['malicious'] == r2.get_json()['malicious']


class TestGCNPath:
    def test_gcn_probability_always_present(self, client):
        """gcn_probability key always in metadata (None when GCN disabled)."""
        resp = client.post('/analyze', json={'code': BENIGN_CODE})
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'gcn_probability' in data['metadata']

    def test_gcn_inference_when_enabled(self, client):
        """When GCN patched active, gcn_probability reflects model output."""
        import sys
        import uuid
        from unittest.mock import MagicMock, patch
        import middleware.app as mapp

        # Unique Python-specific code (type hints ensure Python detection)
        uid = uuid.uuid4().hex[:8]
        unique_code = (
            f"import os\n"
            f"def gcn_test_{uid}(x: int) -> int:\n"
            f"    y: int = x + 1\n"
            f"    return y\n"
        )
        mock_data = MagicMock(name='gcn_data')

        mock_cfg = MagicMock()
        mock_cfg.extract_function_graph.return_value = mock_data
        mock_trainer = MagicMock()
        mock_trainer.predict_gcn.return_value = (True, 0.8)

        extra_modules = {'cfg_extractor': mock_cfg, 'trainerModel_GCN': mock_trainer}
        with patch.dict(sys.modules, extra_modules), \
             patch.object(mapp, '_GCN_ENABLED', True), \
             patch.object(mapp, '_gcn_model', MagicMock(name='gcn_model')), \
             patch.object(mapp, '_gcn_f1', 0.65):
            resp = client.post('/analyze', json={'code': unique_code})

        assert resp.status_code == 200
        data = resp.get_json()
        assert data['metadata']['gcn_probability'] == 0.8


class TestSNNPath:
    def test_snn_temporal_in_metadata_when_enabled(self, client):
        """When SNN enabled+mocked, snn_temporal key appears in metadata."""
        from unittest.mock import MagicMock, patch
        from types import SimpleNamespace

        snn_result = SimpleNamespace(
            anomaly_prob=0.9,
            is_anomalous=True,
            isi_cv=1.2,
            firing_rate_hz=50.0,
            n_events=100,
            inference_ms=3.5,
        )
        mock_profiler = MagicMock()
        mock_profiler.profile.return_value = snn_result

        with patch('middleware.app.SNN_ENABLED', True), \
             patch('middleware.app._snn_profiler', mock_profiler):
            resp = client.post('/analyze', json={'code': BENIGN_CODE})

        assert resp.status_code == 200
        data = resp.get_json()
        assert 'snn_temporal' in data['metadata']
