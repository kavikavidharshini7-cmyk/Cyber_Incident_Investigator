import pandas as pd


REQUIRED_COLUMNS = [
    "id",
    "timestamp",
    "user",
    "source_ip",
    "event_type",
    "resource",
    "status"
]


def validate_logs(df):
    """
    Check whether the uploaded CSV
    contains all required columns.
    """

    missing_columns = [
        column
        for column in REQUIRED_COLUMNS
        if column not in df.columns
    ]

    if missing_columns:
        return False, missing_columns

    return True, []


def parse_logs(df):
    """
    Clean and prepare the security log data.
    """

    df = df.copy()

    # Convert timestamp column
    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )

    # Remove rows with invalid timestamps
    df = df.dropna(
        subset=["timestamp"]
    )

    # Clean text columns
    text_columns = [
        "user",
        "source_ip",
        "event_type",
        "resource",
        "status"
    ]

    for column in text_columns:
        df[column] = (
            df[column]
            .astype(str)
            .str.strip()
        )

    # Sort events chronologically
    df = df.sort_values(
        by="timestamp"
    ).reset_index(drop=True)

    return df


def get_log_statistics(df):
    """
    Generate basic statistics
    from the uploaded security logs.
    """

    statistics = {
        "total_events": len(df),

        "unique_users": df["user"].nunique(),

        "unique_ips": df["source_ip"].nunique(),

        "event_types": df["event_type"].nunique(),

        "failed_events": int(
            (
                df["status"]
                .str.lower()
                == "failed"
            ).sum()
        ),

        "successful_events": int(
            (
                df["status"]
                .str.lower()
                == "successful"
            ).sum()
        )
    }

    return statistics