import pandas as pd


def correlate_by_user(df):
    """
    Group related security events by user.
    """

    correlations = []

    for user in df["user"].dropna().unique():

        user_events = df[
            df["user"] == user
        ].sort_values("timestamp")

        if len(user_events) < 2:
            continue

        correlations.append({
            "user": user,
            "event_count": len(user_events),
            "first_event": user_events.iloc[0]["timestamp"],
            "last_event": user_events.iloc[-1]["timestamp"],
            "ips": list(
                user_events["source_ip"].dropna().unique()
            ),
            "events": list(
                user_events["event_type"].dropna().unique()
            )
        })

    return correlations


def correlate_login_to_access(df):
    """
    Correlate login activity with subsequent
    sensitive resource access.
    """

    chains = []

    for user in df["user"].dropna().unique():

        user_events = df[
            df["user"] == user
        ].sort_values("timestamp")

        successful_logins = user_events[
            (user_events["event_type"].str.lower() == "login") &
            (user_events["status"].str.lower() == "successful")
        ]

        for _, login in successful_logins.iterrows():

            later_events = user_events[
                user_events["timestamp"] > login["timestamp"]
            ]

            sensitive_events = later_events[
                later_events["event_type"].str.lower().isin([
                    "file access",
                    "database access",
                    "file download",
                    "device access"
                ])
            ]

            if not sensitive_events.empty:

                chains.append({
                    "user": user,
                    "login_time": login["timestamp"],
                    "login_ip": login["source_ip"],
                    "related_events": sensitive_events[
                        [
                            "timestamp",
                            "event_type",
                            "resource",
                            "source_ip",
                            "status"
                        ]
                    ].to_dict("records")
                })

    return chains


def correlate_failed_login_success(df):
    """
    Detect a pattern where multiple failed login attempts
    are followed by a successful login.
    """

    correlations = []

    for user in df["user"].dropna().unique():

        user_events = df[
            df["user"] == user
        ].sort_values("timestamp")

        failed_logins = user_events[
            (user_events["event_type"].str.lower() == "login") &
            (user_events["status"].str.lower() == "failed")
        ]

        successful_logins = user_events[
            (user_events["event_type"].str.lower() == "login") &
            (user_events["status"].str.lower() == "successful")
        ]

        for _, success in successful_logins.iterrows():

            previous_failures = failed_logins[
                failed_logins["timestamp"] < success["timestamp"]
            ]

            if not previous_failures.empty:

                correlations.append({
                    "user": user,
                    "failed_attempts": len(previous_failures),
                    "successful_login_time": success["timestamp"],
                    "successful_login_ip": success["source_ip"],
                    "pattern": (
                        "Failed logins followed by "
                        "successful authentication"
                    )
                })

    return correlations


def build_evidence_chain(df):
    """
    Build a combined evidence chain for the incident.
    """

    evidence = {
        "user_correlations": correlate_by_user(df),
        "login_access_chains": correlate_login_to_access(df),
        "authentication_patterns": correlate_failed_login_success(df)
    }

    return evidence


def get_evidence_summary(evidence):
    """
    Create a readable summary of correlated evidence.
    """

    user_count = len(
        evidence["user_correlations"]
    )

    login_access_count = len(
        evidence["login_access_chains"]
    )

    authentication_count = len(
        evidence["authentication_patterns"]
    )

    return {
        "users_with_related_activity": user_count,
        "login_to_access_chains": login_access_count,
        "suspicious_authentication_patterns": authentication_count
    }