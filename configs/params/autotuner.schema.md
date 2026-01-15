# HPPK Parameter Auto-Tuner Schema
Version: 1.0  
Last Updated: 2026-01-05

---

## 1. Purpose

This document defines the **input/output schema** for the HPPK Parameter Auto-Tuner.

The Auto-Tuner is designed to:
- Automatically derive HPPK parameters (L, K, key sizes, security estimates)
- Validate parameter choices against known security constraints
- Generate tables directly usable in academic papers and experiments

This schema serves as a **contract** between:
- experiments
- implementation code
- and academic documentation

---

## 2. Input Schema

### 2.1 Required Fields

| Field | Type | Description |
|---|---|---|
| `security_level` | string | Target security level: `"I"`, `"III"`, `"V"` |
| `log2_p` | integer | Bit length of the prime field size `p` |
| `m` | integer | Number of noise variables |
| `lambda` | integer | Degree of private univariate polynomials (λ), typically `1` |

### 2.2 Optional Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `scheme` | string | `"BOTH"` | `"KEM"`, `"DS"`, or `"BOTH"` |
| `hash` | string | auto | Hash function for DS (`SHA-256`, `SHA-384`, `SHA-512`) |
| `segments` | integer \| string | `"auto"` | Hash segmentation for DS signatures |
| `pk_exposes_mu_nu` | boolean | `false` | Whether DS public key exposes μᵢⱼ, νᵢⱼ values |
| `margin_bits` | integer | `16` | Extra safety margin added to minimum L |

---

## 3. Input Example

```json
{
  "security_level": "III",
  "log2_p": 96,
  "m": 1,
  "lambda": 1,
  "scheme": "BOTH",
  "hash": "SHA-384",
  "segments": "auto",
  "pk_exposes_mu_nu": true,
  "margin_bits": 16
}
"sizes_bytes": {
  "PK": 300,
  "SK": 152,
  "Sig": 208,
  "CT": 0
}
4. Output Schema
4.1 Core Outputs
                           
                           | Field                | Type    | Description                                   |
| -------------------- | ------- | --------------------------------------------- |
| `L_bits_min`         | integer | Minimum hidden ring size (bits)               |
| `L_bits_recommended` | integer | Recommended hidden ring size (with margin)    |
| `K_bits`             | integer | Barrett parameter bit length                  |
| `R_repr`             | string  | Barrett base representation (e.g., `"2^240"`) |

4.2 Size Report

All sizes are expressed in bytes.
"sizes_bytes": {
  "PK": 300,
  "SK": 152,
  "Sig": 208,
  "CT": 0
}
| Field | Description                      |
| ----- | -------------------------------- |
| `PK`  | Public key size                  |
| `SK`  | Private key size                 |
| `Sig` | Digital signature size (DS only) |
| `CT`  | Ciphertext size (KEM only)       |

4.3 Security Estimate
"security_estimate": {
  "bruteforce_hidden_ring": "O(2^L)"
}
| Field                    | Description                                |
| ------------------------ | ------------------------------------------ |
| `bruteforce_hidden_ring` | Estimated complexity of hidden ring attack |

4.4 Warnings
"warnings": [
  "DS public key exposes mu/nu values; key recovery complexity may be reduced.",
  "Recommended K is L + 32 for Barrett stability."
]
Warnings are human-readable explanations describing:

security risks

parameter violations

design trade-offs
4.5 Table Outputs (Paper-Ready)

The Auto-Tuner may generate tables suitable for direct inclusion in papers.

"tables": {
  "table_params_md": "| Security | log2(p) | L | K |",
  "table_sizes_md": "| PK | SK | Sig |",
  "table_params_csv": "Security,log2(p),L,K",
  "table_sizes_csv": "PK,SK,Sig"
}
| Field   | Description                      |
| ------- | -------------------------------- |
| `*_md`  | Markdown tables                  |
| `*_csv` | CSV tables for spreadsheet tools |


