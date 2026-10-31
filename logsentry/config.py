"""Detection policy. These values are examples for our fictional lab."""

from dataclasses import dataclass
from datetime import timedelta
from ipaddress import ip_network
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


@dataclass(frozen=True)
class DetectionSettings:
    """An immutable collection of settings passed to each part of the engine."""

    # FEATURE 1: Legacy auth.log timestamps need a starting year and timezone.
    year: int
    timezone_name: str = "UTC"

    # FEATURE 4: This count covers the entire imported file, without a window.
    repeated_threshold: int = 3

    # FEATURE 5: Five attempts must actually fit inside this time window.
    brute_force_threshold: int = 5
    brute_force_window: timedelta = timedelta(minutes=5)

    # FEATURE 2: Correlate a success with earlier failures of the SAME account.
    success_after_failures_window: timedelta = timedelta(minutes=10)

    # FEATURE 6: Trust is explicit; being a private IP does not imply trust.
    trusted_networks: tuple[str, ...] = ("192.168.1.0/24",)
    normal_start_hour: int = 6
    normal_end_hour: int = 22

    def __post_init__(self) -> None:
        """Reject an invalid policy before reading or analyzing any logs."""
        # Type hints describe expected values, but do not validate user input.
        # In particular, a fractional threshold cannot be used as a list index.
        integer_settings = (
            self.year, self.repeated_threshold, self.brute_force_threshold,
            self.normal_start_hour, self.normal_end_hour,
        )
        if any(type(value) is not int for value in integer_settings):
            raise ValueError("Year, failure thresholds, and hours must be integers.")
        if not 1 <= self.year <= 9999:
            raise ValueError("The log year must be between 1 and 9999.")
        if self.repeated_threshold < 2 or self.brute_force_threshold < 2:
            raise ValueError("Failure thresholds must be at least 2.")
        if not isinstance(self.brute_force_window, timedelta) or self.brute_force_window <= timedelta(0):
            raise ValueError("The brute-force window must be positive.")
        if not isinstance(self.success_after_failures_window, timedelta) or self.success_after_failures_window <= timedelta(0):
            raise ValueError("The success correlation window must be positive.")
        if not 0 <= self.normal_start_hour <= 23:
            raise ValueError("The starting hour must be between 0 and 23.")
        if not 0 <= self.normal_end_hour <= 24:
            raise ValueError("The ending hour must be between 0 and 24.")
        if self.normal_start_hour == self.normal_end_hour:
            raise ValueError("The starting and ending hours must differ.")
        if not isinstance(self.timezone_name, str) or not self.timezone_name:
            raise ValueError("A timezone name is required.")
        try:
            ZoneInfo(self.timezone_name)
        except (ZoneInfoNotFoundError, ValueError) as error:
            raise ValueError(f"Unknown timezone: {self.timezone_name}") from error
        if not isinstance(self.trusted_networks, tuple):
            raise ValueError("Trusted networks must be a tuple of CIDR strings.")
        for network in self.trusted_networks:
            if not isinstance(network, str) or "/" not in network:
                raise ValueError("Trusted networks must use CIDR notation, e.g. 192.168.1.0/24.")
            ip_network(network)  # Strictly validate each configured CIDR network.

    def is_normal_login_hour(self, hour: int) -> bool:
        """Also support working hours that span midnight, e.g. 22:00-06:00."""
        if self.normal_start_hour < self.normal_end_hour:
            return self.normal_start_hour <= hour < self.normal_end_hour
        return hour >= self.normal_start_hour or hour < self.normal_end_hour
