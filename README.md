# Secure Password Generator Pro — Gamility Tools

A modern, high-security, client-side cryptographic password, passphrase, and PIN generator with live Shannon entropy evaluation, brute-force crack-time estimation, and batch export.

---

## 🔒 100% Client-Side Privacy Guarantee

All cryptographic operations leverage the browser's native **`window.crypto.getRandomValues()`** hardware-seeded CSPRNG (Cryptographically Secure Pseudo-Random Number Generator). 

Your generated credentials, passphrases, and preferences are **never transmitted, logged, or uploaded** to remote cloud servers or third-party analytics. 

---

## ✨ Features

- **CSPRNG Security**: Cryptographically strong pseudo-random numbers with zero predictable mathematical bias.
- **Shannon Entropy Analysis**: Live bit-entropy calculation ($E = L \times \log_2(N)$) and brute-force crack-time projections.
- **Customizable Character Sets**:
  - Uppercase Letters (`A-Z`)
  - Lowercase Letters (`a-z`)
  - Numeric Digits (`0-9`)
  - Special Symbols (`!@#$%^&*...`)
  - Exclude Lookalike Characters (e.g. `1, l, I, 0, O, o`)
  - Exclude Ambiguous Symbols (e.g. brackets, quotes, slashes)
- **Multi-Mode Generation**:
  - *Random Password*: Standard high-entropy strings (length 4 to 128 characters).
  - *Memorable Passphrase*: Diceware-style human-readable word combinations with optional hyphens and numbers.
  - *Numeric PIN*: High-speed digits for banking and SIM lock codes.
- **Quick Presets**: Single-click buttons for *Standard Strong (16 chars)*, *Maximum Security (32 chars)*, and *Ultra Defense (64 chars)*.
- **Batch Generator**: Instantly generate 5, 10, or 25 distinct passwords with one-click bulk copy.
- **Session History**: Fast in-memory clipboard access to recently generated keys during your active browser tab session.
- **Responsive Dark Design**: Tailored glassmorphism UI styled for desktop, tablet, and mobile displays.

---

## 📄 Terms & Copyright

Copyright © 2026 [Gamility](https://mahesh-yennam.github.io/Gamility/). All Rights Reserved.  
Proprietary utility software developed exclusively for the [Gamility Platform](https://mahesh-yennam.github.io/Gamility/).
