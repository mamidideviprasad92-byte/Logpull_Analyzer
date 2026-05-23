# analysis/ai_engine.py

import ollama
from textwrap import dedent

DEFAULT_MODEL = "phi3"   # You can change to deepseek-r1 or phi3


def _ask_llm(prompt: str, model: str = DEFAULT_MODEL) -> str:
    try:
        response = ollama.chat(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            stream=False   # <‑‑‑ THIS FIXES THE HANG
        )
        return response["message"]["content"].strip()
    except Exception as e:
        return f"[AI Error] {e}"


def explain_episode(episode_id: int, episode, model: str = DEFAULT_MODEL) -> str:
    """Explain a single crash/reboot episode."""
    crash = episode.crash_event.subtype if episode.crash_event else "No crash"
    reboot = "Reboot" if episode.reboot_event else "No reboot"

    prompt = dedent(f"""
    You are an expert in DOCSIS, XGS-PON, Wi-Fi, embedded systems, and broadband CPE logs.

    Analyze the following crash/reboot episode:

    Episode: {episode_id}
    Crash Status: {crash}
    Reboot Status: {reboot}

    Context Before (last 40 lines):
    {chr(10).join(episode.context_before[-40:])}

    Context After (first 20 lines):
    {chr(10).join(episode.context_after[:20])}

    Provide:
    1. Short summary (2–3 lines)
    2. Likely root cause
    3. Evidence from logs
    4. Recommended next steps
    """)

    return _ask_llm(prompt, model=model)


def summarize_log(df_logs, df_issues, model: str = DEFAULT_MODEL) -> str:
    """Generate an AI summary for the Summary tab."""
    prompt = dedent(f"""
    You are assisting with broadband gateway log analysis.

    Here is structured information:

    Total log lines: {len(df_logs)}
    Total anomalies: {len(df_issues)}

    Anomalies:
    {df_issues.head(20).to_string()}

    Generate:
    - Executive summary (non-technical)
    - Technical summary
    - Key anomalies
    - Risks & recommendations
    """)

    return _ask_llm(prompt, model=model)


def generate_rca(crash_episodes, model: str = DEFAULT_MODEL) -> str:
    """Generate a full RCA across all episodes."""
    ep_text = ""
    for i, ep in enumerate(crash_episodes, start=1):
        ep_text += f"Episode {i}: crash={bool(ep.crash_event)}, reboot={bool(ep.reboot_event)}\n"

    prompt = dedent(f"""
    You are writing a Root Cause Analysis for a broadband CPE.

    Crash/Reboot Episodes:
    {ep_text}

    Produce a formal RCA with:
    - Summary
    - Impact
    - Timeline
    - Root cause
    - Evidence
    - Corrective actions
    - Preventive actions
    """)

    return _ask_llm(prompt, model=model)


def ask_question(context: str, question: str, model: str = DEFAULT_MODEL) -> str:
    """Free-form Q&A about logs."""
    prompt = dedent(f"""
    You are answering questions about cable modem logs.

    Context:
    {context}

    Question:
    {question}

    Provide a precise, evidence-based answer.
    """)

    return _ask_llm(prompt, model=model)