# 🔐 Password Strength Analyzer

A Python-based Password Strength Analyzer that evaluates password security, detects weak patterns, prevents password reuse using SQLite, and generates strong passwords.

## 📌 Features

* Password strength analysis with scoring system
* Detection of:

  * Weak passwords
  * Common passwords
  * Repeated characters
  * Sequential patterns (e.g., `123`, `abc`)
  * Keyboard patterns (e.g., `qwerty`, `asdf`)
* Password history tracking using SQLite
* Strong password generation
* Secure passphrase generation
* Memorable password suggestions
* Detailed feedback and improvement recommendations

## 🛠 Technologies Used

* Python 3.11+
* SQLite3
* Regular Expressions (`re`)
* Hashlib (`hashlib`)
* Secrets (`secrets`)
* Dataclasses (`dataclasses`)

## 📂 Project Structure

```text
Password-Strength-Analyzer/
│
├── password analyzer.py
├── README.md
├── .gitignore
└── password_history.db (generated automatically)
```

## 🚀 How to Run

### Clone the Repository

```bash
git clone https://github.com/tunganaVarun/Password-Strength-Analyzer.git
cd Password-Strength-Analyzer
```

### Run the Program

```bash
python "password analyzer.py"
```

## 📊 Password Strength Levels

| Score    | Strength    |
| -------- | ----------- |
| 0 - 19   | Very Weak   |
| 20 - 39  | Weak        |
| 40 - 59  | Fair        |
| 60 - 79  | Strong      |
| 80 - 100 | Very Strong |

## 🔑 Example Usage

```text
🔐 PASSWORD STRENGTH ANALYZER 🔐

Options:
1. Analyze a password
2. Generate strong passwords
3. Exit
```

### Sample Analysis

```text
Strength: STRONG
Score: 75/100

Feedback:
- Consider using a longer password

Suggestions:
1. BraveTiger483@
2. cloud-river-forest92#
3. T@8gL9!mP2#xR7q
```

## 🔒 Security Features

* SHA-256 password hashing
* Password reuse prevention
* Secure random password generation using Python's `secrets` module
* Common password detection
* Pattern and sequence detection

## 📈 Future Enhancements

* GUI using Tkinter or PyQt
* Password breach checking API integration
* Export analysis reports
* Web-based version using Flask or Django
* Advanced password entropy calculation

## 👨‍💻 Author

**Varun Sai Tungana**

GitHub: https://github.com/tunganaVarun

---

⭐ If you find this project useful, consider giving it a star on GitHub.
