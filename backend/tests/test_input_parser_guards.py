"""Regression tests for untrusted-input parser bounds (lot-6 review).

  - Smart import (/api/v2/import/*): content is size-capped before the parser
    runs its multiple full-content regex + per-block crypto passes.
  - Discovery scanner: a single oversized CIDR target cannot expand into
    millions of host/port jobs (memory-exhaustion DoS).
"""
import json
import pytest


class TestSmartImportSizeCap:
    def test_analyze_rejects_oversized_content(self, auth_client):
        big = 'A' * (5 * 1024 * 1024 + 1)
        r = auth_client.post('/api/v2/import/analyze',
                             data=json.dumps({'content': big}),
                             content_type='application/json')
        assert r.status_code == 413

    def test_execute_rejects_oversized_content(self, auth_client):
        big = 'A' * (5 * 1024 * 1024 + 1)
        r = auth_client.post('/api/v2/import/execute',
                             data=json.dumps({'content': big}),
                             content_type='application/json')
        assert r.status_code == 413

    def test_normal_content_not_rejected_by_cap(self, auth_client):
        # A small invalid blob: must pass the size gate (not 413). The parser
        # then simply finds nothing — any non-413 status proves the cap allows it.
        r = auth_client.post('/api/v2/import/analyze',
                             data=json.dumps({'content': 'not a certificate'}),
                             content_type='application/json')
        assert r.status_code != 413


class TestDiscoveryCidrCap:
    def test_subnet_scan_rejects_huge_cidr(self, app):
        with app.app_context():
            from services.discovery import DiscoveryService
            svc = DiscoveryService()
            with pytest.raises(ValueError, match='max'):
                svc.start_subnet_scan(cidr='10.0.0.0/8', ports=[443])

    def test_start_scan_rejects_huge_cidr_target(self, app):
        with app.app_context():
            from services.discovery import DiscoveryService
            svc = DiscoveryService()
            with pytest.raises(ValueError, match='max'):
                svc.start_scan(targets=['10.0.0.0/8'], ports=[443])


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
