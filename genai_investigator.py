import os
import json
import requests
import pandas as pd

from dotenv import load_dotenv


load_dotenv()


OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

MODEL = "openrouter/auto"


def prepare_evidence(df):
    """
    Convert cybersecurity logs into a compact
    evidence structure for GenAI analysis.
    """

    evidence = []

    for _, row in df.iterrows():

        evidence.append({
            "timestamp": str(row["timestamp"]),
            "user": str(row["user"]),
            "source_ip": str(row["source_ip"]),
            "event_type": str(row["event_type"]),
            "resource": str(row["resource"]),
            "status": str(row["status"])
        })

    return evidence


def build_investigation_prompt(evidence):
    """
    Create a structured investigation prompt
    for the GenAI model.
    """

    evidence_text = json.dumps(
        evidence,
        indent=2
    )

    prompt = f"""
You are a cybersecurity incident investigation assistant.

Analyze the following security log evidence.

Your analysis must be evidence-grounded.
Do not invent events or facts that are not present
in the supplied evidence.

SECURITY LOG EVIDENCE:
{evidence_text}

Provide the investigation in this exact structure:

1. Incident Overview
2. Observed Suspicious Activity
3. Evidence Correlation
4. Attack / Incident Timeline
5. Possible Root Cause
6. Risk and Impact
7. Recommended Investigation Steps
8. Important Evidence to Verify
9. Final Investigation Conclusion

For every important conclusion, explain which
observed evidence supports it.

Clearly distinguish between:
- Confirmed observations
- Investigative hypotheses

Do not claim that an incident is confirmed
unless the evidence actually proves it.
"""


    return prompt


def call_openrouter(prompt):
    """
    Send the investigation request to OpenRouter.
    """

    api_key = os.getenv(
        "OPENROUTER_API_KEY"
    )

    if not api_key:
        return (
            "❌ OPENROUTER_API_KEY was not found "
            "in the .env file."
        )

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a careful cybersecurity "
                    "incident investigation assistant. "
                    "Use only the supplied evidence."
                )
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.2
    }

    try:

        response = requests.post(
            OPENROUTER_URL,
            headers=headers,
            json=payload,
            timeout=120
        )

        response.raise_for_status()

        result = response.json()

    except requests.exceptions.Timeout:

        return (
            "❌ GenAI request timed out. "
            "Please try again."
        )

    except requests.exceptions.RequestException as error:

        return (
            "❌ OpenRouter request failed.\n\n"
            f"Error: {error}"
        )

    except ValueError:

        return (
            "❌ OpenRouter returned an invalid response."
        )

    choices = result.get(
        "choices",
        []
    )

    if not choices:

        return (
            "❌ AI returned no choices.\n\n"
            f"Raw response:\n{result}"
        )

    message = choices[0].get(
        "message",
        {}
    )

    content = message.get(
        "content"
    )

    if content is None:

        content = message.get(
            "reasoning"
        )

    if content is None:

        content = choices[0].get(
            "text"
        )

    if content is None:

        return (
            "❌ AI response was received, "
            "but no readable text was returned.\n\n"
            f"Raw response:\n{result}"
        )

    return str(content)


def generate_investigation(df):
    """
    Main GenAI investigation function.
    """

    if df is None or df.empty:

        return (
            "❌ No security log data is available "
            "for investigation."
        )

    evidence = prepare_evidence(df)

    prompt = build_investigation_prompt(
        evidence
    )

    return call_openrouter(
        prompt
    )


def generate_investigation_from_evidence(
    evidence
):
    """
    Run GenAI investigation directly from
    already prepared evidence.
    """

    if not evidence:

        return (
            "❌ No evidence is available "
            "for GenAI investigation."
        )

    prompt = build_investigation_prompt(
        evidence
    )

    return call_openrouter(
        prompt
    )