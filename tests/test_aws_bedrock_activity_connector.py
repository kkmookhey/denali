import json
from datetime import UTC, datetime

from denali.connectors.aws_bedrock_activity import (
    EVENT_NAMES,
    AwsBedrockActivityConnector,
)


class FakeCloudTrail:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def lookup_events(self, **request):
        self.calls.append(request)
        return self.responses.pop(0)


def _event(*, event_id="event-1", event_name="Converse"):
    return {
        "EventId": event_id,
        "EventName": event_name,
        "EventTime": datetime(2026, 8, 27, 12, tzinfo=UTC),
        "Username": "ni-sales-agent",
        "CloudTrailEvent": json.dumps(
            {
                "eventID": event_id,
                "eventName": event_name,
                "eventTime": "2026-08-27T12:00:00Z",
                "awsRegion": "ap-south-1",
                "recipientAccountId": "331145994818",
                "userIdentity": {
                    "type": "AssumedRole",
                    "arn": "arn:aws:sts::331145994818:assumed-role/AnnaRole/ni-sales-agent",
                    "sessionContext": {
                        "sessionIssuer": {
                            "arn": "arn:aws:iam::331145994818:role/AnnaRole"
                        }
                    },
                },
                "requestParameters": {"modelId": "global.anthropic.claude-sonnet"},
            }
        ),
    }


def test_collects_management_events_and_links_assumed_role_to_issuer():
    client = FakeCloudTrail(
        [{"Events": [_event()]}] + [{"Events": []} for _ in EVENT_NAMES[1:]]
    )
    start = datetime(2026, 8, 27, tzinfo=UTC)
    end = datetime(2026, 8, 28, tzinfo=UTC)
    batch = AwsBedrockActivityConnector(
        account_id="331145994818", region="ap-south-1", cloudtrail_client=client
    ).collect(start_time=start, end_time=end)

    assert batch.coverage[0].state.value == "complete"
    assert len(batch.activities) == 1
    actor = batch.activities[0].entities[0]
    assert actor.external_uid.endswith("assumed-role/AnnaRole/ni-sales-agent")
    assert actor.asset.natural_key == "arn:aws:iam::331145994818:role/AnnaRole"
    assert all(call["StartTime"] == start and call["EndTime"] == end for call in client.calls)
    assert [call["LookupAttributes"][0]["AttributeValue"] for call in client.calls] == list(
        EVENT_NAMES
    )


def test_repeated_pagination_token_is_partial_not_silent_complete():
    client = FakeCloudTrail(
        [
            {"Events": [_event()], "NextToken": "again"},
            {"Events": [_event()], "NextToken": "again"},
        ]
        + [{"Events": []} for _ in EVENT_NAMES[1:]]
    )
    batch = AwsBedrockActivityConnector(
        account_id="331145994818", region="ap-south-1", cloudtrail_client=client
    ).collect(
        start_time=datetime(2026, 8, 27, tzinfo=UTC),
        end_time=datetime(2026, 8, 28, tzinfo=UTC),
    )
    assert batch.coverage[0].state.value == "partial"
    assert "repeated pagination token" in batch.coverage[0].detail
    assert len(batch.activities) == 1


def test_api_failure_is_bounded_and_does_not_echo_secret_message():
    class SecretError(RuntimeError):
        response = {"Error": {"Code": "AccessDeniedException"}}

    class BrokenCloudTrail:
        def lookup_events(self, **request):
            raise SecretError("credential=do-not-print")

    batch = AwsBedrockActivityConnector(
        account_id="331145994818", region="ap-south-1", cloudtrail_client=BrokenCloudTrail()
    ).collect(
        start_time=datetime(2026, 8, 27, tzinfo=UTC),
        end_time=datetime(2026, 8, 28, tzinfo=UTC),
    )
    assert batch.coverage[0].state.value == "failed"
    assert batch.activities == ()
    assert batch.coverage[0].detail == "cloudtrail:LookupEvents: AccessDeniedException"
