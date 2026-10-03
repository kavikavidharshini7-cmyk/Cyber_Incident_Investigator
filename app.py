import streamlit as st
import pandas as pd
import plotly.express as px

from modules.log_parser import (
    validate_logs,
    parse_logs,
    get_log_statistics
)

from modules.anomaly_detector import (
    detect_suspicious_activity,
    get_alert_summary
)

from modules.evidence_correlator import (
    build_evidence_chain,
    get_evidence_summary
)

from modules.timeline_builder import (
    build_timeline,
    generate_timeline_summary,
    identify_critical_timeline_events
)

from modules.severity_engine import (
    assess_incident_severity,
    generate_severity_summary
)

from modules.root_cause import (
    analyze_root_cause,
    generate_root_cause_summary
)

from modules.genai_investigator import (
    generate_investigation
)

from modules.response_engine import (
    generate_response_recommendations,
    generate_response_summary
)

from modules.report_generator import (
    generate_report
)

from modules.database import (
    initialize_database,
    save_investigation,
    get_all_investigations,
    get_database_statistics
)


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Cyber Investigator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    .main-title {
        font-size: 38px;
        font-weight: 800;
        margin-bottom: 5px;
    }

    .sub-title {
        font-size: 20px;
        font-weight: 600;
        margin-bottom: 20px;
    }

    .info-card {
        padding: 20px;
        border-radius: 12px;
        border: 1px solid #d9e2ec;
        background-color: #f8fafc;
        margin-bottom: 15px;
    }

    .feature-card {
        padding: 20px;
        border-radius: 12px;
        border: 1px solid #d9e2ec;
        background-color: white;
        min-height: 170px;
    }

    .workflow-box {
        padding: 18px;
        border-radius: 12px;
        border: 1px solid #d9e2ec;
        background-color: #f8fafc;
        text-align: center;
        margin-bottom: 10px;
    }

    .research-box {
        padding: 20px;
        border-radius: 12px;
        border: 1px solid #d9e2ec;
        background-color: #ffffff;
        margin-bottom: 12px;
    }

    .challenge-box {
        padding: 18px;
        border-radius: 12px;
        border: 1px solid #d9e2ec;
        background-color: #f8fafc;
        margin-bottom: 15px;
    }

    .evidence-box {
        padding: 15px;
        border-radius: 10px;
        border-left: 5px solid #4f46e5;
        background-color: #f8fafc;
        margin-bottom: 10px;
    }

    .stat-box {
        padding: 18px;
        border-radius: 12px;
        border: 1px solid #d9e2ec;
        background-color: #ffffff;
        text-align: center;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

initialize_database()


# ============================================================
# SESSION STATE
# ============================================================

defaults = {
    "staff_df": None,
    "student_df": None,
    "staff_alerts": [],
    "staff_evidence": {},
    "staff_timeline": None,
    "staff_severity": None,
    "staff_root_cause": None,
    "staff_recommendations": [],
    "staff_genai_report": None,
    "staff_pdf_path": None,
    "staff_file_name": "",

    "student_challenge_revealed": False,
    "student_genai_report": None,

    "challenge_ip": "185.220.101.45",
    "challenge_first_event": "Repeated failed login attempts",
    "challenge_resource": "Student Database",
    "challenge_root_cause": "Possible Compromised User Credentials"
}

for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.markdown("## 🛡️ Cyber Investigator")
st.sidebar.markdown("---")

page = st.sidebar.radio(
    "Navigation",
    [
        "🏠 Dashboard",
        "👨‍💻 Staff Investigation",
        "🎓 Student Investigation",
        "📊 Investigation History"
    ]
)

st.sidebar.markdown("---")

st.sidebar.info(
    "This system is an investigation assistant. "
    "It analyzes supplied evidence and provides "
    "investigative findings and defensive recommendations."
)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def load_dataframe(uploaded_file):

    try:
        df = pd.read_csv(uploaded_file)

        valid, missing_columns = validate_logs(df)

        if not valid:
            st.error(
                "CSV file is missing required columns: "
                + ", ".join(missing_columns)
            )
            return None

        df = parse_logs(df)

        return df

    except Exception as error:
        st.error(f"Unable to read CSV file: {error}")
        return None


def run_staff_analysis(df):

    st.session_state.staff_df = df

    alerts = detect_suspicious_activity(df)
    evidence = build_evidence_chain(df)
    timeline = build_timeline(df)
    severity = assess_incident_severity(df)
    root_cause = analyze_root_cause(df)

    recommendations = generate_response_recommendations(
        df,
        severity,
        root_cause
    )

    st.session_state.staff_alerts = alerts
    st.session_state.staff_evidence = evidence
    st.session_state.staff_timeline = timeline
    st.session_state.staff_severity = severity
    st.session_state.staff_root_cause = root_cause
    st.session_state.staff_recommendations = recommendations
    st.session_state.staff_genai_report = None
    st.session_state.staff_pdf_path = None


def create_student_simulation():

    data = [
        {
            "id": 1,
            "timestamp": "2026-10-03 09:00:12",
            "user": "student_admin",
            "source_ip": "192.168.1.20",
            "event_type": "Login",
            "resource": "Student Account",
            "status": "Failed"
        },
        {
            "id": 2,
            "timestamp": "2026-10-03 09:01:05",
            "user": "student_admin",
            "source_ip": "192.168.1.20",
            "event_type": "Login",
            "resource": "Student Account",
            "status": "Failed"
        },
        {
            "id": 3,
            "timestamp": "2026-10-03 09:02:18",
            "user": "student_admin",
            "source_ip": "192.168.1.20",
            "event_type": "Login",
            "resource": "Student Account",
            "status": "Failed"
        },
        {
            "id": 4,
            "timestamp": "2026-10-03 09:04:31",
            "user": "student_admin",
            "source_ip": "185.220.101.45",
            "event_type": "Login",
            "resource": "Student Account",
            "status": "Successful"
        },
        {
            "id": 5,
            "timestamp": "2026-10-03 09:05:10",
            "user": "student_admin",
            "source_ip": "185.220.101.45",
            "event_type": "Device Access",
            "resource": "Unknown Device",
            "status": "Detected"
        },
        {
            "id": 6,
            "timestamp": "2026-10-03 09:06:45",
            "user": "student_admin",
            "source_ip": "185.220.101.45",
            "event_type": "File Access",
            "resource": "Student_Records.xlsx",
            "status": "Accessed"
        },
        {
            "id": 7,
            "timestamp": "2026-10-03 09:08:22",
            "user": "student_admin",
            "source_ip": "185.220.101.45",
            "event_type": "Database Access",
            "resource": "Student Database",
            "status": "Accessed"
        },
        {
            "id": 8,
            "timestamp": "2026-10-03 09:10:14",
            "user": "student_admin",
            "source_ip": "185.220.101.45",
            "event_type": "File Download",
            "resource": "Student_Records.xlsx",
            "status": "Downloaded"
        }
    ]

    df = pd.DataFrame(data)

    return parse_logs(df)


def run_student_analysis(df):

    st.session_state.student_df = df
    st.session_state.student_challenge_revealed = False
    st.session_state.student_genai_report = None


def calculate_student_challenge_score(
    suspicious_ip,
    first_suspicious_event,
    sensitive_resource,
    root_cause
):

    score = 0

    if suspicious_ip == "185.220.101.45":
        score += 1

    if first_suspicious_event == "Repeated failed login attempts":
        score += 1

    if sensitive_resource == "Student Database":
        score += 1

    if root_cause == "Possible Compromised User Credentials":
        score += 1

    return score


def show_student_challenge(df):

    st.markdown("## 🎯 Investigator Challenge")

    st.markdown(
        """
        <div class="challenge-box">

        <h3>🕵️ What do you think happened?</h3>

        Before seeing the system's investigation conclusion,
        examine the simulated evidence and make your own
        investigation decisions.

        <br>

        <b>Tip:</b> Look at the sequence of login attempts,
        source IP addresses, device activity and resource access.

        </div>
        """,
        unsafe_allow_html=True
    )

    suspicious_ip = st.radio(
        "### Question 1 — Which IP should be investigated first?",
        [
            "192.168.1.20",
            "185.220.101.45",
            "127.0.0.1",
            "No suspicious IP"
        ],
        key="challenge_ip"
    )

    first_suspicious_event = st.radio(
        "### Question 2 — What is the first major suspicious pattern?",
        [
            "Repeated failed login attempts",
            "Successful login",
            "File download",
            "Database access"
        ],
        key="challenge_first_event"
    )

    sensitive_resource = st.radio(
        "### Question 3 — Which resource is most sensitive in this simulation?",
        [
            "Student Account",
            "Unknown Device",
            "Student Database",
            "Student_Records.xlsx"
        ],
        key="challenge_resource"
    )

    root_cause = st.radio(
        "### Question 4 — What is the most likely investigative hypothesis?",
        [
            "Possible Compromised User Credentials",
            "Normal Student Activity",
            "Hardware Failure",
            "Database Maintenance"
        ],
        key="challenge_root_cause"
    )

    if st.button(
        "🔎 Reveal Investigation",
        key="reveal_student_investigation"
    ):

        st.session_state.student_challenge_revealed = True

    if st.session_state.student_challenge_revealed:

        score = calculate_student_challenge_score(
            suspicious_ip,
            first_suspicious_event,
            sensitive_resource,
            root_cause
        )

        st.markdown("---")
        st.markdown("### 🏆 Investigation Result")

        col1, col2 = st.columns(2)

        with col1:
            st.metric(
                "Investigator Score",
                f"{score}/4"
            )

        with col2:

            if score == 4:
                st.success("🎉 Excellent investigation!")
            elif score >= 2:
                st.info("👍 Good investigation. Review the evidence again.")
            else:
                st.warning(
                    "🔍 Re-examine the event sequence and evidence."
                )

        st.markdown("### 🔐 Evidence-Based Answers")

        st.write(
            "**Suspicious IP:** `185.220.101.45`"
        )

        st.write(
            "**First major suspicious pattern:** "
            "`Repeated failed login attempts`"
        )

        st.write(
            "**Most sensitive resource:** "
            "`Student Database`"
        )

        st.write(
            "**Investigative hypothesis:** "
            "`Possible Compromised User Credentials`"
        )

        st.markdown("### 🔗 How the Evidence Connects")

        st.markdown(
            """
            <div class="evidence-box">

            <b>Step 1:</b> Three failed login attempts were observed.

            <br><br>

            <b>Step 2:</b> A successful login then occurred from
            a different IP address.

            <br><br>

            <b>Step 3:</b> An unknown device was detected.

            <br><br>

            <b>Step 4:</b> Sensitive student information was accessed.

            <br><br>

            <b>Step 5:</b> A student record file was downloaded.

            </div>
            """,
            unsafe_allow_html=True
        )


# ============================================================
# DASHBOARD
# ============================================================

if page == "🏠 Dashboard":

    st.markdown(
        '<div class="main-title">🛡️ Cyber Investigator</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="sub-title">'
        'GenAI-Based Cybersecurity Incident Investigation Assistant'
        '</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        """
        <div class="info-card">

        <b>🎯 Project Objective</b>

        <br><br>

        Cyber Investigator is a software-based cybersecurity
        investigation assistant that analyzes supplied security
        evidence, correlates suspicious events, reconstructs
        incident timelines and uses Generative AI to produce
        evidence-grounded investigative findings.

        <br><br>

        The system is designed to support investigators,
        students and cybersecurity learning without executing
        offensive security actions.

        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("## 🔄 Investigation Pipeline")

    pipeline = [
        "📄 Security Logs",
        "⚙️ Log Preprocessing",
        "🚨 Suspicious Activity Detection",
        "🔗 Evidence Correlation",
        "⏱️ Timeline Reconstruction",
        "🧠 GenAI Investigation",
        "🔍 Root Cause Hypothesis",
        "⚠️ Risk Assessment",
        "🛡️ Defensive Recommendations",
        "📑 Investigation Report"
    ]

    cols = st.columns(5)

    for index, step in enumerate(pipeline):

        with cols[index % 5]:

            st.markdown(
                f"""
                <div class="workflow-box">
                <b>{step}</b>
                </div>
                """,
                unsafe_allow_html=True
            )

    st.markdown("---")

    st.markdown("## 🚀 Key Features")

    col1, col2, col3 = st.columns(3)

    with col1:

        st.markdown(
            """
            <div class="feature-card">

            ### 🚨 Suspicious Activity

            Detect repeated failed logins,
            unknown devices, suspicious IP changes
            and sensitive resource access.

            </div>
            """,
            unsafe_allow_html=True
        )

    with col2:

        st.markdown(
            """
            <div class="feature-card">

            ### 🔗 Evidence Correlation

            Connect authentication events,
            device activity and resource access
            to identify related security events.

            </div>
            """,
            unsafe_allow_html=True
        )

    with col3:

        st.markdown(
            """
            <div class="feature-card">

            ### 🧠 GenAI Investigation

            Generate evidence-grounded investigation
            findings, hypotheses and recommended
            investigation steps.

            </div>
            """,
            unsafe_allow_html=True
        )

    col4, col5, col6 = st.columns(3)

    with col4:

        st.markdown(
            """
            <div class="feature-card">

            ### ⏱️ Timeline Reconstruction

            Reconstruct the sequence of security
            events to understand how an incident
            developed.

            </div>
            """,
            unsafe_allow_html=True
        )

    with col5:

        st.markdown(
            """
            <div class="feature-card">

            ### 📑 Investigation Report

            Generate structured reports containing
            evidence, findings, severity,
            root-cause hypotheses and recommendations.

            </div>
            """,
            unsafe_allow_html=True
        )

    with col6:

        st.markdown(
            """
            <div class="feature-card">

            ### 🎓 Student Investigation Lab

            Let students investigate simulated
            cybersecurity incidents and solve
            evidence-based investigation challenges.

            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("---")

    st.markdown("## 🔬 Research Focus")

    research_items = [
        (
            "Evidence-Grounded GenAI",
            "AI conclusions are generated from supplied security evidence rather than unsupported assumptions."
        ),
        (
            "Explainable Investigation",
            "The system presents evidence, reasoning and investigative hypotheses separately."
        ),
        (
            "Timeline Reconstruction",
            "Related events are organized chronologically to support incident understanding."
        ),
        (
            "Human-in-the-Loop Verification",
            "AI findings are treated as investigative hypotheses that require verification."
        )
    ]

    for title, description in research_items:

        st.markdown(
            f"""
            <div class="research-box">

            <b>🔬 {title}</b>

            <br>

            {description}

            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("---")

    st.markdown("## 🎬 Live Demonstration Flow")

    demo_col1, demo_col2 = st.columns(2)

    with demo_col1:

        st.markdown(
            """
            <div class="info-card">

            ### 👨‍💻 Staff Investigation

            1. Upload security logs  
            2. Detect suspicious activity  
            3. Correlate evidence  
            4. Reconstruct timeline  
            5. Assess severity  
            6. Generate root-cause hypothesis  
            7. Run GenAI investigation  
            8. Generate PDF report  

            </div>
            """,
            unsafe_allow_html=True
        )

    with demo_col2:

        st.markdown(
            """
            <div class="info-card">

            ### 🎓 Student Investigation

            1. Start safe simulation  
            2. Examine simulated logs  
            3. Solve Investigator Challenge  
            4. Reveal evidence-based investigation  
            5. View suspicious activity  
            6. Explore evidence correlation  
            7. Understand incident timeline  
            8. Run GenAI investigation  

            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("---")

    st.markdown("## 🛡️ Investigation Philosophy")

    st.info(
        "Cyber Investigator is an investigation-support system. "
        "It analyzes available evidence and provides defensive "
        "recommendations. AI-generated conclusions are treated "
        "as investigative hypotheses and should be verified "
        "using additional evidence."
    )


# ============================================================
# STAFF INVESTIGATION
# ============================================================

elif page == "👨‍💻 Staff Investigation":

    st.title("👨‍💻 Staff Investigation")

    st.write(
        "Upload security logs and perform a structured cybersecurity "
        "incident investigation."
    )

    uploaded_file = st.file_uploader(
        "📄 Upload Security Log CSV",
        type=["csv"]
    )

    if uploaded_file is not None:

        df = load_dataframe(uploaded_file)

        if df is not None:

            st.session_state.staff_file_name = uploaded_file.name

            st.success(
                f"Successfully loaded {len(df)} security events."
            )

            statistics = get_log_statistics(df)

            st.markdown("## 📊 Log Statistics")

            c1, c2, c3, c4, c5, c6 = st.columns(6)

            c1.metric(
                "Total Events",
                statistics["total_events"]
            )

            c2.metric(
                "Users",
                statistics["unique_users"]
            )

            c3.metric(
                "IP Addresses",
                statistics["unique_ips"]
            )

            c4.metric(
                "Event Types",
                statistics["event_types"]
            )

            c5.metric(
                "Failed Events",
                statistics["failed_events"]
            )

            c6.metric(
                "Successful Events",
                statistics["successful_events"]
            )

            st.markdown("## 📄 Uploaded Security Logs")

            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True
            )

            if st.button(
                "🔍 Analyze Security Incident",
                type="primary"
            ):

                run_staff_analysis(df)

                st.success(
                    "Security incident analysis completed."
                )

            if st.session_state.staff_df is not None:

                df = st.session_state.staff_df

                st.markdown("---")

                st.markdown("## 🚨 Suspicious Activity Detection")

                alerts = st.session_state.staff_alerts
                alert_summary = get_alert_summary(alerts)

                a1, a2, a3, a4 = st.columns(4)

                a1.metric(
                    "Total Alerts",
                    alert_summary["total_alerts"]
                )

                a2.metric(
                    "High",
                    alert_summary["high_alerts"]
                )

                a3.metric(
                    "Medium",
                    alert_summary["medium_alerts"]
                )

                a4.metric(
                    "Low",
                    alert_summary["low_alerts"]
                )

                for alert in alerts:

                    st.warning(
                        f"**{alert['type']}** — "
                        f"{alert['message']}"
                    )

                st.markdown("---")

                st.markdown("## 🔗 Evidence Correlation")

                evidence = st.session_state.staff_evidence
                evidence_summary = get_evidence_summary(evidence)

                e1, e2, e3 = st.columns(3)

                e1.metric(
                    "Related Users",
                    evidence_summary[
                        "users_with_related_activity"
                    ]
                )

                e2.metric(
                    "Login → Access Chains",
                    evidence_summary[
                        "login_to_access_chains"
                    ]
                )

                e3.metric(
                    "Authentication Patterns",
                    evidence_summary[
                        "suspicious_authentication_patterns"
                    ]
                )

                auth_patterns = evidence[
                    "authentication_patterns"
                ]

                if auth_patterns:

                    st.markdown(
                        "### 🔐 Authentication Correlation"
                    )

                    st.dataframe(
                        pd.DataFrame(auth_patterns),
                        use_container_width=True,
                        hide_index=True
                    )

                login_chains = evidence[
                    "login_access_chains"
                ]

                if login_chains:

                    st.markdown(
                        "### 🔗 Login → Resource Access Chain"
                    )

                    for chain in login_chains:

                        st.write(
                            f"**User:** {chain['user']}"
                        )

                        st.write(
                            f"**Login IP:** {chain['login_ip']}"
                        )

                        st.write(
                            f"**Login Time:** {chain['login_time']}"
                        )

                        st.dataframe(
                            pd.DataFrame(
                                chain["related_events"]
                            ),
                            use_container_width=True,
                            hide_index=True
                        )

                st.markdown("---")

                st.markdown("## ⏱️ Incident Timeline")

                timeline = st.session_state.staff_timeline

                st.write(
                    generate_timeline_summary(timeline)
                )

                st.dataframe(
                    timeline,
                    use_container_width=True,
                    hide_index=True
                )

                critical_events = identify_critical_timeline_events(
                    timeline
                )

                if critical_events:

                    st.markdown(
                        "### ⚠️ Critical Timeline Events"
                    )

                    st.dataframe(
                        pd.DataFrame(critical_events),
                        use_container_width=True,
                        hide_index=True
                    )

                st.markdown("---")

                st.markdown("## ⚠️ Severity Assessment")

                severity = st.session_state.staff_severity

                s1, s2, s3 = st.columns(3)

                s1.metric(
                    "Risk Score",
                    f"{severity['risk_score']}/10"
                )

                s2.metric(
                    "Severity",
                    severity["severity"]
                )

                s3.metric(
                    "Assessment",
                    severity["severity_label"]
                )

                st.info(
                    generate_severity_summary(severity)
                )

                st.markdown("### Reasons")

                for reason in severity["reasons"]:

                    st.write(f"• {reason}")

                st.markdown("---")

                st.markdown("## 🧠 Root Cause Analysis")

                root_cause = st.session_state.staff_root_cause

                st.warning(
                    "The following is an investigative hypothesis "
                    "based on the available evidence. It is not "
                    "treated as a confirmed fact."
                )

                st.write(
                    "**Possible Root Cause**"
                )

                st.info(
                    root_cause["primary_cause"]
                )

                st.write(
                    "**Confidence**"
                )

                st.write(
                    root_cause["confidence"]
                )

                st.markdown("### Supporting Evidence")

                for evidence_item in root_cause[
                    "supporting_evidence"
                ]:

                    st.write(
                        f"• {evidence_item}"
                    )

                st.markdown("### Alternative Hypotheses")

                for hypothesis in root_cause[
                    "alternative_hypotheses"
                ]:

                    st.write(
                        f"• {hypothesis}"
                    )

                st.markdown("### Investigation Reasoning")

                st.write(
                    root_cause["reasoning"]
                )

                st.info(
                    root_cause["investigation_status"]
                )

                st.markdown("---")

                st.markdown("## 🛡️ Defensive Recommendations")

                recommendations = (
                    st.session_state.staff_recommendations
                )

                st.info(
                    generate_response_summary(
                        recommendations
                    )
                )

                recommendation_df = pd.DataFrame(
                    recommendations
                )

                st.dataframe(
                    recommendation_df,
                    use_container_width=True,
                    hide_index=True
                )

                st.markdown("---")

                st.markdown("## 🤖 GenAI Investigation Engine")

                st.write(
                    "The GenAI engine analyzes the security evidence "
                    "and produces an evidence-grounded investigation report."
                )

                if st.button(
                    "🧠 Run GenAI Investigation"
                ):

                    with st.spinner(
                        "GenAI is investigating the incident..."
                    ):

                        report = generate_investigation(
                            df
                        )

                        st.session_state.staff_genai_report = report

                if st.session_state.staff_genai_report:

                    st.markdown(
                        st.session_state.staff_genai_report
                    )

                st.markdown("---")

                st.markdown("## 📑 Investigation Report")

                if st.button(
                    "📄 Generate PDF Investigation Report"
                ):

                    with st.spinner(
                        "Generating investigation report..."
                    ):

                        report_result = generate_report(
                            df,
                            severity,
                            root_cause,
                            recommendations,
                            st.session_state.staff_genai_report
                        )

                        st.session_state.staff_pdf_path = (
                            report_result["pdf_path"]
                        )

                        investigation_id = save_investigation(
                            incident_name=(
                                "Uploaded Security Incident"
                            ),
                            total_events=len(df),
                            risk_score=severity[
                                "risk_score"
                            ],
                            severity=severity[
                                "severity"
                            ],
                            root_cause=root_cause[
                                "primary_cause"
                            ],
                            confidence=root_cause[
                                "confidence"
                            ],
                            report_path=report_result[
                                "pdf_path"
                            ]
                        )

                        st.success(
                            f"Investigation saved successfully. "
                            f"Record ID: {investigation_id}"
                        )

                if st.session_state.staff_pdf_path:

                    pdf_path = st.session_state.staff_pdf_path

                    st.success(
                        "PDF investigation report generated."
                    )

                    with open(
                        pdf_path,
                        "rb"
                    ) as pdf_file:

                        st.download_button(
                            label="⬇️ Download Investigation Report",
                            data=pdf_file,
                            file_name=(
                                pdf_path.split("\\")[-1]
                                .split("/")[-1]
                            ),
                            mime="application/pdf"
                        )


# ============================================================
# STUDENT INVESTIGATION
# ============================================================

elif page == "🎓 Student Investigation":

    st.title("🎓 Student Investigation Lab")

    st.write(
        "Explore a safe simulated cybersecurity incident "
        "and understand how investigators correlate evidence."
    )

    if st.button(
        "🚀 Start Student Simulation",
        type="primary"
    ):

        df = create_student_simulation()

        run_student_analysis(df)

        st.success(
            f"Student simulation loaded with {len(df)} security events."
        )

    if st.session_state.student_df is not None:

        df = st.session_state.student_df

        st.success(
            f"Student simulation loaded with {len(df)} security events."
        )

        st.markdown("## 📄 Simulated Security Logs")

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True
        )

        statistics = get_log_statistics(df)

        st.markdown("## 📊 Simulation Statistics")

        c1, c2, c3, c4, c5, c6 = st.columns(6)

        c1.metric(
            "Total Events",
            statistics["total_events"]
        )

        c2.metric(
            "Users",
            statistics["unique_users"]
        )

        c3.metric(
            "IP Addresses",
            statistics["unique_ips"]
        )

        c4.metric(
            "Event Types",
            statistics["event_types"]
        )

        c5.metric(
            "Failed Events",
            statistics["failed_events"]
        )

        c6.metric(
            "Successful Events",
            statistics["successful_events"]
        )

        show_student_challenge(df)

        st.markdown("---")

        st.markdown("## 🚨 Suspicious Activity Detection")

        alerts = detect_suspicious_activity(df)
        alert_summary = get_alert_summary(alerts)

        a1, a2, a3, a4 = st.columns(4)

        a1.metric(
            "Total Alerts",
            alert_summary["total_alerts"]
        )

        a2.metric(
            "High",
            alert_summary["high_alerts"]
        )

        a3.metric(
            "Medium",
            alert_summary["medium_alerts"]
        )

        a4.metric(
            "Low",
            alert_summary["low_alerts"]
        )

        for alert in alerts:

            st.warning(
                f"**{alert['type']}** — "
                f"{alert['message']}"
            )

        st.markdown("---")

        st.markdown("## 🔗 Evidence Correlation")

        evidence = build_evidence_chain(df)
        evidence_summary = get_evidence_summary(evidence)

        e1, e2, e3 = st.columns(3)

        e1.metric(
            "Related Users",
            evidence_summary[
                "users_with_related_activity"
            ]
        )

        e2.metric(
            "Login → Access Chains",
            evidence_summary[
                "login_to_access_chains"
            ]
        )

        e3.metric(
            "Authentication Patterns",
            evidence_summary[
                "suspicious_authentication_patterns"
            ]
        )

        auth_patterns = evidence[
            "authentication_patterns"
        ]

        if auth_patterns:

            st.markdown(
                "### 🔐 Authentication Correlation"
            )

            st.dataframe(
                pd.DataFrame(auth_patterns),
                use_container_width=True,
                hide_index=True
            )

        login_chains = evidence[
            "login_access_chains"
        ]

        if login_chains:

            st.markdown(
                "### 🔗 Login → Resource Access Chain"
            )

            for chain in login_chains:

                st.write(
                    f"**User:** {chain['user']}"
                )

                st.write(
                    f"**Login IP:** {chain['login_ip']}"
                )

                st.write(
                    f"**Login Time:** {chain['login_time']}"
                )

                st.dataframe(
                    pd.DataFrame(
                        chain["related_events"]
                    ),
                    use_container_width=True,
                    hide_index=True
                )

        st.markdown("---")

        st.markdown("## ⏱️ Incident Timeline")

        timeline = build_timeline(df)

        st.write(
            generate_timeline_summary(timeline)
        )

        st.dataframe(
            timeline,
            use_container_width=True,
            hide_index=True
        )

        critical_events = identify_critical_timeline_events(
            timeline
        )

        if critical_events:

            st.markdown(
                "### ⚠️ Critical Timeline Events"
            )

            st.dataframe(
                pd.DataFrame(critical_events),
                use_container_width=True,
                hide_index=True
            )

        st.markdown("---")

        st.markdown("## ⚠️ Severity Assessment")

        severity = assess_incident_severity(df)

        s1, s2, s3 = st.columns(3)

        s1.metric(
            "Risk Score",
            f"{severity['risk_score']}/10"
        )

        s2.metric(
            "Severity",
            severity["severity"]
        )

        s3.metric(
            "Assessment",
            severity["severity_label"]
        )

        st.info(
            generate_severity_summary(severity)
        )

        st.markdown("### Reasons")

        for reason in severity["reasons"]:

            st.write(
                f"• {reason}"
            )

        st.markdown("---")

        st.markdown("## 🧠 Root Cause Analysis")

        root_cause = analyze_root_cause(df)

        st.warning(
            "The following is an investigative hypothesis "
            "based on the available evidence. It is not "
            "treated as a confirmed fact."
        )

        st.write(
            "**Possible Root Cause**"
        )

        st.info(
            root_cause["primary_cause"]
        )

        st.write(
            "**Confidence**"
        )

        st.write(
            root_cause["confidence"]
        )

        st.markdown("### Supporting Evidence")

        for evidence_item in root_cause[
            "supporting_evidence"
        ]:

            st.write(
                f"• {evidence_item}"
            )

        st.markdown("### Alternative Hypotheses")

        for hypothesis in root_cause[
            "alternative_hypotheses"
        ]:

            st.write(
                f"• {hypothesis}"
            )

        st.markdown("### Investigation Reasoning")

        st.write(
            root_cause["reasoning"]
        )

        st.info(
            root_cause["investigation_status"]
        )

        st.markdown("---")

        st.markdown("## 🤖 GenAI Investigation Engine")

        st.write(
            "The GenAI engine analyzes the simulated security "
            "evidence and produces an evidence-grounded "
            "investigation report."
        )

        if st.button(
            "🧠 Run Student GenAI Investigation"
        ):

            with st.spinner(
                "GenAI is investigating the simulation..."
            ):

                report = generate_investigation(df)

                st.session_state.student_genai_report = report

        if st.session_state.student_genai_report:

            st.markdown(
                st.session_state.student_genai_report
            )


# ============================================================
# INVESTIGATION HISTORY
# ============================================================

elif page == "📊 Investigation History":

    st.title("📊 Investigation History")

    st.write(
        "Review previously saved cybersecurity investigations."
    )

    statistics = get_database_statistics()

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Total Investigations",
        statistics["total_investigations"]
    )

    c2.metric(
        "High / Critical",
        statistics["high_or_critical"]
    )

    c3.metric(
        "Medium",
        statistics["medium"]
    )

    c4.metric(
        "Low",
        statistics["low"]
    )

    investigations = get_all_investigations()

    if investigations:

        st.markdown("## 📋 Investigation Records")

        history_df = pd.DataFrame(
            investigations
        )

        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True
        )

        if "severity" in history_df.columns:

            severity_counts = (
                history_df["severity"]
                .value_counts()
                .reset_index()
            )

            severity_counts.columns = [
                "Severity",
                "Count"
            ]

            if not severity_counts.empty:

                st.markdown(
                    "## 📈 Investigation Severity Distribution"
                )

                fig = px.bar(
                    severity_counts,
                    x="Severity",
                    y="Count",
                    title="Investigation Severity Distribution"
                )

                st.plotly_chart(
                    fig,
                    use_container_width=True
                )

    else:

        st.info(
            "No investigation records are available yet. "
            "Run a Staff Investigation and generate a report "
            "to create the first history record."
        )