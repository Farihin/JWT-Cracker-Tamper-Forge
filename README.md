# JWT-Cracker & Tamper Forge

**Attack Category:** Web Application Attack (Authentication & Session Token Security Testing)  
**Course:** IKB31603 — Ethical Hacking (UniKL MIIT)  

**JWT-Cracker & Tamper Forge** is an offline, local-first command-line security testing tool built in Python to audit JSON Web Token (JWT) implementations for weak HMAC secrets, `alg: none` signature-stripping flaws, claim tampering vulnerabilities, and `RS256`-to-`HS256` algorithm confusion risks.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Attack Lifecycle Mapping](#attack-lifecycle-mapping)
3. [Project Structure](#project-structure)
4. [Installation & Setup](#installation--setup)
5. [Step-by-Step Usage Guide](#step-by-step-usage-guide)
6. [Running Unit Tests](#running-unit-tests)
7. [Ethical Considerations & Design Decisions](#ethical-considerations--design-decisions)
8. [Rules of Engagement (RoE)](#rules-of-engagement-roe)
9. [Responsible Disclosure Policy](#responsible-disclosure-policy)
10. [Legal Disclaimer](#legal-disclaimer)
11. [Limitations & Safe Scope Notes](#limitations--safe-scope-notes)
12. [License](#license)

---

## Project Overview

Modern web applications frequently rely on JSON Web Tokens (JWTs) to manage user sessions and role-based access control. When token validation logic or signing keys are misconfigured, attackers can forge tokens or escalate privileges. This tool allows authorized security testers and students to:

- **Inspect** JWT headers, payloads, and signature encodings without verifying against a remote server.
- **Crack** weakly signed `HS256`, `HS384`, and `HS512` tokens offline using a local wordlist dictionary attack.
- **Tamper** with JWT claims (e.g., escalating `role=user` to `role=admin`) and test signature bypass techniques (`alg: none`, re-signing with a recovered secret, and `RS256` $\rightarrow$ `HS256` key-confusion).

---

## Attack Lifecycle Mapping

This tool maps directly to multiple phases of the ethical hacking lifecycle in a controlled, offline environment:

| Lifecycle Phase | Tool Capability | Description |
| :--- | :--- | :--- |
| **1. Reconnaissance & Analysis** | `inspect` | Decodes Base64URL-encoded JWT header and payload fields to identify the signing algorithm (`alg`), token type (`typ`), user identity claims (`sub`, `role`), and expiration timestamps (`exp`). |
| **2. Vulnerability Assessment** | `crack` | Performs an offline dictionary check against `HS256`/`HS384`/`HS512` signatures using `wordlists/common_jwt_secrets.txt` to detect weak or predictable signing secrets. |
| **3. Controlled Exploitation (PoC)** | `tamper` | Generates proof-of-concept tokens demonstrating privilege escalation (`--set role=admin`), signature stripping (`--none-alg`), or `RS256`-to-`HS256` algorithm confusion (`--rs-to-hs-confusion`) on authorized test tokens. |
| **4. Post-Test Verification & Reporting** | `pytest` / Local Output | Validates remediation through automated unit tests and keeps all output strictly local for inclusion in security audit reports. |

---

## Project Structure

```text
jwt-cracker-tamper-forge/
├── core/
│   ├── __init__.py
│   ├── cracker.py        # Offline dictionary attack logic with KillSwitch support
│   ├── jwt_utils.py      # Base64URL encoding/decoding, token parsing, HMAC signing/verification
│   ├── safety.py         # Authorization banner, scope enforcement, and clean KillSwitch handler
│   └── tamper.py         # Claim modification, alg:none bypass, and RS256->HS256 confusion logic
├── tests/
│   └── test_core.py      # Pytest unit test suite
├── wordlists/
│   └── common_jwt_secrets.txt
├── main.py               # CLI entry point (argparse)
├── requirements.txt      # Python dependencies
├── LICENSE               # Open-source license
└── README.md             # Project documentation
```

---

## Installation & Setup

- **GitHub Repository:** https://github.com/Farihin/JWT-Cracker-Tamper-Forge

### Prerequisites
- **Python 3.10+** installed and available in your terminal (`python --version`)
- **Visual Studio Code** (or any terminal supporting PowerShell / Bash)

### Setup Steps

1. **Clone the repository and open the project folder:**
   ```powershell
   git clone https://github.com/Farihin/JWT-Cracker-Tamper-Forge.git
   cd JWT-Cracker-Tamper-Forge
   ```
   *(If you already have the project files locally on your machine, open the project folder containing `main.py` directly in VS Code instead of cloning.)*

2. **Create and activate a virtual environment (recommended):**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. **Install dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

---

## Step-by-Step Usage Guide

> **Authorization Prompt:** Every command prints the legal disclaimer and requires you to type `I AM AUTHORIZED TO TEST THIS TOKEN` before executing.

### Step 1: Generate a Local Test JWT Token
Because the tool operates offline on token strings you supply, generate a sample `HS256` test token in your VS Code PowerShell terminal and store it in a session variable `$token`:

```powershell
$token = python -c "from core import jwt_utils; print(jwt_utils.build_token({'alg':'HS256','typ':'JWT'}, {'sub':'1001','user':'student','role':'user'}, b'secret', 'HS256'))"
echo $token
```

*(Note: PowerShell session variables like `$token` are cleared when you close VS Code. Re-run this step whenever you open a new terminal session.)*

### Step 2: Inspect the Token (Decode Header & Payload)
Decode the token to view its structure and claims without sending any network traffic:

```powershell
python main.py inspect --token $token
```

### Step 3: Crack a Weak HMAC Secret (Offline Dictionary Attack)
Test whether the token is signed with a weak password from the included wordlist:

```powershell
python main.py crack --token $token --wordlist wordlists/common_jwt_secrets.txt
```

### Step 4: Tamper — Algorithm `none` Bypass Test
Generate a modified token with `"alg": "none"` and an empty signature to test whether a target application fails to enforce signature verification:

```powershell
python main.py tamper --token $token --none-alg
```

### Step 5: Tamper — Escalate Claims & Re-Sign with a Known/Recovered Secret
Modify the `role` claim from `user` to `admin` and re-sign the token using the secret recovered in Step 3 (`secret`):

```powershell
python main.py tamper --token $token --set role=admin --secret secret
```

### Step 6: Tamper — `RS256` to `HS256` Key-Confusion Test (Optional / Lab Key Required)
If testing an `RS256`-configured application with a public key (`pub.pem`) from an authorized lab target:

```powershell
python main.py tamper --token <rs256-token> --rs-to-hs-confusion --public-key pub.pem
```

*(Ensure any temporary `.pem` test files are deleted or excluded via `.gitignore` before committing to GitHub.)*

### View All CLI Flags & Help
```powershell
python main.py --help
python main.py inspect --help
python main.py crack --help
python main.py tamper --help
```

---

## Running Unit Tests

Run the included `pytest` suite to verify token parsing, HMAC verification, dictionary cracking, and tampering functions:

```powershell
pytest -q
```

---

## Ethical Considerations & Design Decisions

1. **Zero Network Requests (Offline-Only Architecture):** The tool strictly parses, verifies, and signs token strings locally. It contains no HTTP client or live brute-force functionality, preventing accidental denial-of-service or unauthorized traffic against live servers.
2. **Mandatory Startup Legal Disclaimer & Explicit Confirmation:** Upon execution, `core/safety.py` prints a legal warning citing Malaysia's **Computer Crimes Act 1997** and blocks execution unless the user explicitly types `I AM AUTHORIZED TO TEST THIS TOKEN`.
3. **Safe Defaults & Scope Restriction:** Default testing examples and scope checks are restricted to `localhost`, `127.0.0.1`, `example.com`, and local test tokens.
4. **No Default Data Exfiltration or Persistent Secret Logging:** Discovered secrets and forged tokens are printed only to local stdout unless the user explicitly specifies a local output path.
5. **Clean Kill Switch (`Ctrl+C` / `KillSwitch`):** Long-running wordlist operations monitor `core.safety.KillSwitch` so the user can abort immediately and cleanly without leaving corrupted files behind.

---

## Rules of Engagement (RoE)

Any use of **JWT-Cracker & Tamper Forge** must adhere to the following Rules of Engagement:

- **Authorized Scope:** Only test tokens issued by applications you own, local lab environments (`localhost` / `127.0.0.1`), or systems covered by a signed written Rules of Engagement / bug bounty scope.
- **Time Windows:** Testing against shared or organizational staging environments must occur strictly within pre-approved maintenance or assessment windows.
- **Permitted Techniques:** Offline JWT decoding (`inspect`), offline wordlist verification (`crack`), and local token structure generation (`tamper`) for proof-of-concept validation.
- **Prohibited Actions:**
  - Live credential stuffing or high-rate token replay against production endpoints.
  - Testing tokens belonging to third-party accounts or unauthorized systems.
  - Exfiltrating, sharing, or publishing captured production tokens or private keys.
- **Emergency Stop Procedures:** Press `Ctrl+C` at any time to trigger the built-in `KillSwitch` and immediately terminate execution.

---

## Responsible Disclosure Policy

If this tool identifies a weak JWT secret or signature verification flaw during an authorized assessment:

1. **Who to Notify:** Report the finding directly to the system owner, application security team, or designated organizational security contact (or your course lecturer if discovered within a lab exercise).
2. **When to Report:** Notify the owner immediately upon confirming a critical authentication bypass (such as `alg: none` acceptance or a trivially guessable signing key), before any public discussion.
3. **How to Report:** Provide a private, encrypted report containing:
  - Affected endpoint/service and token algorithm (`HS256`, `RS256`, etc.).
  - Step-by-step reproduction using redacted test tokens (never include real user tokens or production secrets).
  - Remediation guidance (e.g., rotating to a high-entropy 256-bit+ secret, enforcing an explicit algorithm allowlist on verification, and rejecting `alg: none`).

---

## Legal Disclaimer

This software is developed strictly for **educational coursework (IKB31603 Ethical Hacking at UniKL MIIT)** and **authorized security testing**. Under Malaysia's **Computer Crimes Act 1997** (and equivalent cybercrime laws internationally), unauthorized access, token forgery, or authentication bypass against any computer system or network you do not own or lack explicit written permission to test is a criminal offense, regardless of intent. The authors accept no liability for misuse of this tool.

---

## Limitations & Safe Scope Notes

- **Dictionary-Bound Cracking:** The `crack` module only detects secrets present in the supplied wordlist; strong randomly generated secrets (256-bit+) cannot be recovered via dictionary attack.
- **Offline Verification Only:** Generating a tampered token (`tamper`) proves how a token can be structured, but confirming whether an application is vulnerable requires validating the token against your own local/authorized test backend.
- **Asymmetric Key Requirement:** The `--rs-to-hs-confusion` option requires a valid RSA public key PEM file (`--public-key`) obtained from the authorized target environment.

---

## License

This project is licensed under the terms specified in the [LICENSE](LICENSE) file.
## Rules of Engagement & Scope
- Only test JWT tokens and endpoints on authorized targets (localhost by default; explicit authorization required for any other host).
- Do not run tampering or cracking workflows against production systems or unauthorized third-party environments.

## Responsible Disclosure & Legal Notice
- Report discovered vulnerabilities privately to the system or application owner before public disclosure.
- Built strictly for educational and authorized security auditing under IKB31603 Ethical Hacking (UniKL MIIT).
