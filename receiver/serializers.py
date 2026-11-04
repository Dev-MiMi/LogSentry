"""Versioned transport records: observations are not automatically login events."""

from datetime import datetime, timezone

from rest_framework import serializers

from .storage import IDENTIFIER


MAX_BODY_BYTES = 256 * 1024
MAX_BATCH_EVENTS = 100


class StrictSerializer(serializers.Serializer):
    def to_internal_value(self, data):
        if isinstance(data, dict) and set(data) - set(self.fields):
            raise serializers.ValidationError({"non_field_errors": ["Unknown fields are not accepted."]})
        return super().to_internal_value(data)


class AwareTimestamp(serializers.CharField):
    def __init__(self, **kwargs):
        super().__init__(max_length=64, trim_whitespace=False, **kwargs)

    def to_internal_value(self, data):
        value = super().to_internal_value(data)
        try:
            if "T" not in value:
                raise ValueError()
            timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if timestamp.utcoffset() is None:
                raise ValueError()
            return timestamp.astimezone(timezone.utc).isoformat()
        except (ValueError, OverflowError):
            raise serializers.ValidationError("Use an ISO timestamp with T and an explicit UTC offset.")


class EventSerializer(StrictSerializer):
    event_id = serializers.UUIDField()
    platform = serializers.ChoiceField(choices=["linux", "termux", "android"])
    source = serializers.RegexField(regex=r"\A" + IDENTIFIER + r"\Z", max_length=128)
    event_type = serializers.RegexField(regex=r"\A" + IDENTIFIER + r"\Z", max_length=128)
    observed_at = AwareTimestamp()
    occurred_at = AwareTimestamp(allow_null=True, default=None)
    message = serializers.CharField(max_length=8192, trim_whitespace=False, allow_blank=True)

    def validate_message(self, value):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise serializers.ValidationError("Invalid Unicode in message.")
        return value


class BatchSerializer(StrictSerializer):
    schema_version = serializers.IntegerField(min_value=1, max_value=1)
    events = EventSerializer(many=True, allow_empty=False, max_length=MAX_BATCH_EVENTS)

    def validate(self, data):
        ids = [event["event_id"] for event in data["events"]]
        if len(ids) != len(set(ids)):
            raise serializers.ValidationError("Event IDs must be unique within a batch.")
        # Store JSON primitives, normalizing UUID spelling for stable retry IDs.
        for event in data["events"]:
            event["event_id"] = str(event["event_id"])
        return data
