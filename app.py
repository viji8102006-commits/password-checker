"""
Password Strength Checker — Flask backend
Task 02: Evaluates password security and returns a strength rating
(weak / medium / strong) plus specific improvement suggestions.
"""

import re
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# A small sample of extremely common passwords / patterns to flag outright.
# In a production system this list would be much longer (e.g. loaded from
# the "10k most common passwords" dataset).
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "password1",
    "111111", "12345678", "letmein", "iloveyou", "admin", "welcome",
    "monkey", "dragon", "football", "qwerty123", "1q2w3e4r", "sunshine",
}

SPECIAL_CHARS = r"""!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`"""


def analyze_password(password: str) -> dict:
    """Run all checks on a password and return a structured result."""

    if not password:
        return {
            "score": 0,
            "max_score": 7,
            "strength": "weak",
            "checks": {},
            "suggestions": ["Enter a password to analyze."],
        }

    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(f"[{re.escape(SPECIAL_CHARS)}]", password))
    has_repeats = bool(re.search(r"(.)\1{2,}", password))          # aaa, 111
    has_sequence = bool(re.search(
        r"(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwer|asdf)",
        password.lower()
    ))
    is_common = password.lower() in COMMON_PASSWORDS

    checks = {
        "length_8": length >= 8,
        "length_12": length >= 12,
        "has_lowercase": has_lower,
        "has_uppercase": has_upper,
        "has_digit": has_digit,
        "has_special_char": has_special,
        "no_common_password": not is_common,
        "no_obvious_pattern": not (has_repeats or has_sequence),
    }

    # --- Scoring ---------------------------------------------------------
    score = 0
    if checks["length_8"]:
        score += 1
    if checks["length_12"]:
        score += 1
    if checks["has_lowercase"]:
        score += 1
    if checks["has_uppercase"]:
        score += 1
    if checks["has_digit"]:
        score += 1
    if checks["has_special_char"]:
        score += 1
    if checks["no_obvious_pattern"]:
        score += 1

    max_score = 7

    # Common passwords are an automatic hard cap, regardless of other points.
    if is_common:
        score = min(score, 1)

    if score <= 2:
        strength = "weak"
    elif score <= 4:
        strength = "medium"
    else:
        strength = "strong"

    # --- Suggestions -------------------------------------------------------
    suggestions = []
    if is_common:
        suggestions.append("This is one of the most commonly used passwords — choose something unique.")
    if not checks["length_8"]:
        suggestions.append("Use at least 8 characters (12+ is better).")
    elif not checks["length_12"]:
        suggestions.append("Consider lengthening it to 12+ characters for stronger security.")
    if not has_upper:
        suggestions.append("Add at least one uppercase letter (A–Z).")
    if not has_lower:
        suggestions.append("Add at least one lowercase letter (a–z).")
    if not has_digit:
        suggestions.append("Add at least one number (0–9).")
    if not has_special:
        suggestions.append("Add a special character (e.g. ! @ # $ % &).")
    if has_repeats:
        suggestions.append("Avoid repeating the same character 3+ times in a row.")
    if has_sequence:
        suggestions.append("Avoid predictable sequences like '1234' or 'qwer'.")
    if not suggestions:
        suggestions.append("Great password! No major weaknesses detected.")

    return {
        "score": score,
        "max_score": max_score,
        "strength": strength,
        "checks": checks,
        "suggestions": suggestions,
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    result = analyze_password(password)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
