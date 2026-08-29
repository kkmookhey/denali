from datetime import UTC, datetime

from denali.connectors.gcp_vertex_activity import GcpVertexActivityConnector


class Entry:
    def __init__(self, payload):
        self.payload = payload

    def to_api_repr(self):
        return self.payload


class FakeLogging:
    def __init__(self, entries):
        self.entries = entries
        self.calls = []

    def list_entries(self, **request):
        self.calls.append(request)
        return iter(self.entries)


def test_collects_vertex_entries_with_bounded_filter():
    client = FakeLogging(
        [
            Entry(
                {
                    "insertId": "vertex-live-1",
                    "timestamp": "2026-08-27T12:00:00Z",
                    "resource": {"labels": {"location": "us-central1"}},
                    "protoPayload": {
                        "serviceName": "aiplatform.googleapis.com",
                        "methodName": "google.cloud.aiplatform.v1.PredictionService.Predict",
                        "resourceName": "projects/p/locations/us-central1/endpoints/e",
                        "authenticationInfo": {"principalEmail": "analyst@example.com"},
                    },
                }
            )
        ]
    )
    batch = GcpVertexActivityConnector(project_id="vertex-test", logging_client=client).collect(
        start_time=datetime(2026, 8, 27, tzinfo=UTC),
        end_time=datetime(2026, 8, 28, tzinfo=UTC),
    )
    assert batch.coverage[0].state.value == "complete"
    assert len(batch.activities) == 1
    assert batch.activities[0].provider == "gcp_vertex_ai"
    request = client.calls[0]
    assert request["resource_names"] == ["projects/vertex-test"]
    assert 'protoPayload.serviceName="aiplatform.googleapis.com"' in request["filter_"]
    assert "2026-08-27" in request["filter_"] and "2026-08-28" in request["filter_"]


def test_permission_error_is_failed_coverage_without_message_leak():
    class PermissionFailure(RuntimeError):
        code = 403

    class BrokenLogging:
        def list_entries(self, **request):
            raise PermissionFailure("token=do-not-print")

    batch = GcpVertexActivityConnector(
        project_id="vertex-test", logging_client=BrokenLogging()
    ).collect(
        start_time=datetime(2026, 8, 27, tzinfo=UTC),
        end_time=datetime(2026, 8, 28, tzinfo=UTC),
    )
    assert batch.coverage[0].state.value == "failed"
    assert batch.coverage[0].detail == "logging:ListEntries: 403"
