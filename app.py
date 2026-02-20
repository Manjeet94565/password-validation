from flask import Flask, request, jsonify, render_template
import re
import math

app = Flask(__name__)

# ─── Common weak passwords blacklist ───────────────────────────────────────────
COMMON_PASSWORDS = {
    "password", "password1", "123456", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon", "baseball",
    "iloveyou", "master", "sunshine", "ashley", "bailey", "passw0rd",
    "shadow", "123123", "654321", "superman", "qazwsx", "michael",
    "football", "password123", "admin", "welcome", "login", "hello",
    "charlie", "donald", "password2", "qwerty123", "123qwe",
}

# ─── Keyboard walk patterns ────────────────────────────────────────────────────
KEYBOARD_WALKS = [
    "qwerty", "asdfgh", "zxcvbn", "qwertyu", "asdfghj", "zxcvbnm",
    "1234567", "abcdefg", "7654321", "gfedcba", "aaaaaaa", "1111111",
]

# ─── Entropy calculation ───────────────────────────────────────────────────────
def calculate_entropy(password: str) -> float:
    charset = 0
    if re.search(r"[a-z]", password):      charset += 26
    if re.search(r"[A-Z]", password):      charset += 26
    if re.search(r"\d", password):          charset += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\;'/`~]", password): charset += 32
    if charset == 0:
        return 0.0
    return len(password) * math.log2(charset)

# ─── Core validation ──────────────────────────────────────────────────────────
def validate_password(password: str) -> dict:
    errors   = []
    warnings = []
    score    = 0  # 0–100

    # 1. Minimum length
    if len(password) < 12:
        errors.append("Must be at least 12 characters long.")
    elif len(password) >= 16:
        score += 20
    else:
        score += 10

    # 2. Maximum length guard (DoS prevention)
    if len(password) > 128:
        errors.append("Must not exceed 128 characters.")

    # 3. Uppercase letter
    if not re.search(r"[A-Z]", password):
        errors.append("Must contain at least one uppercase letter (A–Z).")
    else:
        score += 10

    # 4. Lowercase letter
    if not re.search(r"[a-z]", password):
        errors.append("Must contain at least one lowercase letter (a–z).")
    else:
        score += 10

    # 5. Digit
    if not re.search(r"\d", password):
        errors.append("Must contain at least one digit (0–9).")
    else:
        score += 10

    # 6. Special character
    special_pattern = r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\;'/`~]"
    if not re.search(special_pattern, password):
        errors.append("Must contain at least one special character (!@#$%^&* etc.).")
    else:
        score += 15

    # 7. Multiple special characters bonus
    if len(re.findall(special_pattern, password)) >= 2:
        score += 5

    # 8. Common passwords blacklist
    if password.lower() in COMMON_PASSWORDS:
        errors.append("Password is too common. Please choose a more unique password.")

    # 9. Repeating characters (e.g. aaa, 111)
    if re.search(r"(.)\1{2,}", password):
        errors.append("Must not contain 3 or more repeated consecutive characters (e.g. 'aaa', '111').")
    else:
        score += 5

    # 10. Sequential characters (abc, 123)
    def has_sequential(s, step=1):
        for i in range(len(s) - 2):
            if ord(s[i+1]) - ord(s[i]) == step and ord(s[i+2]) - ord(s[i+1]) == step:
                return True
        return False

    if has_sequential(password.lower()) or has_sequential(password, step=-1):
        warnings.append("Avoid sequential characters (e.g. 'abc', '123', 'cba').")
        score = max(0, score - 5)

    # 11. Keyboard walk patterns
    p_lower = password.lower()
    for walk in KEYBOARD_WALKS:
        if walk in p_lower or walk[::-1] in p_lower:
            warnings.append(f"Avoid keyboard walk patterns (e.g. 'qwerty', 'asdf').")
            score = max(0, score - 10)
            break

    # 12. Starts/ends with digit (minor penalty)
    if password[0].isdigit() or password[-1].isdigit():
        warnings.append("Avoid starting or ending with a digit for better strength.")

    # 13. Whitespace not allowed
    if re.search(r"\s", password):
        errors.append("Must not contain whitespace characters.")

    # 14. Only one character class — very weak
    classes = sum([
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"\d", password)),
        bool(re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\;'/`~]", password)),
    ])
    if classes == 1:
        errors.append("Must use at least 3 different character classes.")

    # 15. Entropy check
    entropy = calculate_entropy(password)
    if entropy < 50:
        errors.append(f"Password entropy too low ({entropy:.1f} bits). Add more variety.")
    elif entropy >= 80:
        score += 25
    elif entropy >= 60:
        score += 15
    else:
        score += 5

    # Clamp score
    score = min(100, max(0, score))

    # Strength label
    if errors:
        strength = "Weak ❌"
    elif score >= 85:
        strength = "Very Strong 💪"
    elif score >= 65:
        strength = "Strong ✅"
    elif score >= 45:
        strength = "Moderate ⚠️"
    else:
        strength = "Weak ❌"

    return {
        "valid":    len(errors) == 0,
        "score":    score,
        "strength": strength,
        "entropy":  round(entropy, 2),
        "errors":   errors,
        "warnings": warnings,
    }

# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/validate", methods=["POST"])
def validate():
    data     = request.get_json(force=True)
    password = data.get("password", "")
    result   = validate_password(password)
    return jsonify(result)

# ─── Run ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, port=5000)
