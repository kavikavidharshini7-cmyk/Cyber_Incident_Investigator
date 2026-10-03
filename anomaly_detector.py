import pandas as pd


def detect_failed_logins(df, threshold=3):
    """
    Detect repeated failed login attempts.
    """

    alerts = []

    login_events = df[
        df["event_type"].str.lower() == "login"
    ]

    failed_logins = login_events[
        login_events["status"].str.lower() == "failed"
    ]

    if not failed_logins.empty:
        user_counts = (
            failed_logins
            .groupby("user")
            .size()
        )

        for user, count in user_counts.items():
            if count >= threshold:
                alerts.append({
                    "type": "Repeated Failed Login",
                    "severity": "High",
                    "message": (
                        f"{count} failed login attempts "
                        f"detected for user '{user}'."
                    )
                })

    return alerts


def detect_unknown_devices(df):
    """
    Detect access from unknown devices.
    """

    alerts = []

    unknown_device_events = df[
        df["event_type"].str.lower() == "device access"
    ]

    unknown_device_events = unknown_device_events[
        unknown_device_events["resource"]
        .str.lower()
        .str.contains("unknown")
    ]

    for _, row in unknown_device_events.iterrows():
        alerts.append({
            "type": "Unknown Device",
            "severity": "High",
            "message": (
                f"Unknown device detected for user "
                f"'{row['user']}' from IP {row['source_ip']}."
            )
        })

    return alerts


def detect_sensitive_access(df):
    """
    Detect access to sensitive files or databases.
    """

    alerts = []

    sensitive_keywords = [
        "salary",
        "employee",
        "database",
        "confidential",
        "password",
        "financial",
        "admin"
    ]

    for _, row in df.iterrows():

        resource = str(
            row["resource"]
        ).lower()

        matched = any(
            keyword in resource
            for keyword in sensitive_keywords
        )

        if matched:
            alerts.append({
                "type": "Sensitive Resource Access",
                "severity": "High",
                "message": (
                    f"Sensitive resource '{row['resource']}' "
                    f"was accessed by user '{row['user']}'."
                )
            })

    return alerts


def detect_suspicious_ip_change(df):
    """
    Detect successful login from a different IP
    after failed login attempts.
    """

    alerts = []

    login_events = df[
        df["event_type"].str.lower() == "login"
    ].sort_values("timestamp")

    for user in login_events["user"].unique():

        user_logs = login_events[
            login_events["user"] == user
        ]

        failed_ips = set(
            user_logs[
                user_logs["status"].str.lower() == "failed"
            ]["source_ip"]
        )

        successful_logs = user_logs[
            user_logs["status"].str.lower() == "successful"
        ]

        for _, row in successful_logs.iterrows():

            if row["source_ip"] not in failed_ips and failed_ips:

                alerts.append({
                    "type": "Suspicious IP Change",
                    "severity": "High",
                    "message": (
                        f"Successful login for user '{user}' "
                        f"occurred from a different IP: "
                        f"{row['source_ip']}."
                    )
                })

    return alerts


def detect_suspicious_activity(df):
    """
    Run all anomaly detection rules.
    """

    alerts = []

    alerts.extend(
        detect_failed_logins(df)
    )

    alerts.extend(
        detect_unknown_devices(df)
    )

    alerts.extend(
        detect_sensitive_access(df)
    )

    alerts.extend(
        detect_suspicious_ip_change(df)
    )

    return alerts


def get_alert_summary(alerts):
    """
    Generate summary information from alerts.
    """

    total_alerts = len(alerts)

    high_alerts = sum(
        1
        for alert in alerts
        if alert["severity"] == "High"
    )

    medium_alerts = sum(
        1
        for alert in alerts
        if alert["severity"] == "Medium"
    )

    low_alerts = sum(
        1
        for alert in alerts
        if alert["severity"] == "Low"
    )

    return {
        "total_alerts": total_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts
    }