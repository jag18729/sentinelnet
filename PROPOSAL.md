# SentinelNet: AI-Powered Network Intrusion Detection System

## A PyTorch Security Research Project

**Author:** Rafael Garcia
**Affiliation:** CSUN Layer 8 Cybersecurity Research | vandine.us
**Status:** Proposed
**Target Completion:** June 2026 (pre-fellowship)

---

## Abstract

SentinelNet is a deep learning-based network intrusion detection system (NIDS) built on PyTorch that classifies network traffic as benign or malicious across multiple attack categories. The project serves dual purposes: producing a functional security tool deployable on real infrastructure (PA-220 syslog feeds, Prometheus/Grafana integration) and demonstrating empirical ML research methodology relevant to AI security. The model is trained on the CICIDS2017 and CSE-CIC-IDS2018 datasets, fine-tuned with synthetic traffic generated from the author's home lab environment, and served via FastAPI on a Raspberry Pi cluster. Adversarial robustness testing is a core research component, evaluating how evasion attacks degrade detection accuracy and what defensive techniques mitigate them.

---

## Motivation

Most network intrusion detection systems rely on signature-based rules or shallow ML models (Random Forest, XGBoost) that require manual feature engineering for every new attack pattern. At NASA JPL, I built Python automation that scanned firewall policies for compliance drift, and the fundamental limitation was always the same: static rules cannot generalize.

Deep learning models trained on raw or minimally processed network flows can potentially detect novel attack patterns without explicit rule encoding. This project investigates whether a PyTorch-based classifier, deployed on constrained hardware, can match or exceed traditional NIDS accuracy while maintaining the adversarial robustness required for production security systems.

The adversarial robustness component is the research contribution. A detection model that achieves 99% accuracy on clean data but collapses under evasion attacks is useless in practice. Understanding how attackers can manipulate network traffic to evade ML-based detection, and building defenses against those manipulations, is a core AI security research question.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       DATA PIPELINE                          │
│                                                              │
│  CICIDS2017 ──┐                                             │
│  CSE-CIC-IDS2018 ──┼──▶ Preprocessing ──▶ HuggingFace       │
│  Home Lab Synthetic ─┘   (normalize,       Datasets         │
│                          augment)          (versioned)      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      MODEL TRAINING                          │
│                                                              │
│  Encoder: 1D-CNN + BiLSTM hybrid                            │
│  ┌─────────┐    ┌──────────┐    ┌──────────────┐           │
│  │ Conv1D  │──▶ │ BiLSTM   │──▶ │ Classifier   │           │
│  │ (Local) │    │ (Seq)    │    │ (Multi-class)│           │
│  └─────────┘    └──────────┘    └──────────────┘           │
│                                                              │
│  + Adversarial Training (FGSM, PGD, C&W attacks)            │
│  + Tracking: wandb, MLflow, Optuna                          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 INFERENCE & DEPLOYMENT                       │
│                                                              │
│  Pi1: FastAPI + ONNX Runtime (<50ms latency)                │
│  PA-220 syslog ──▶ rsyslog (pi0) ──▶ SentinelNet ──▶ Grafana│
│  Prometheus metrics, drift detection, alerting              │
└─────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

### Core ML
| Tool | Purpose |
|------|---------|
| PyTorch 2.x | Model development, training, adversarial attacks |
| ONNX Runtime | Production inference on Pi1 (2-5x faster on ARM) |
| HuggingFace Datasets | Data versioning, caching, streaming |
| HuggingFace Model Hub | Model sharing and versioning |

### Adversarial ML (Research Component)
| Tool | Purpose |
|------|---------|
| CleverHans | Reference FGSM, PGD, C&W implementations |
| ART (IBM) | Adversarial attack/defense framework |
| Custom PyTorch | Hand-implemented for deeper understanding |

### Experiment Management
| Tool | Purpose |
|------|---------|
| Weights & Biases | Experiment tracking, hyperparameter sweeps |
| MLflow | Model versioning (already in GuardQuote) |
| Optuna | Bayesian hyperparameter optimization |

### Infrastructure (Existing Stack)
| Tool | Already Have |
|------|-------------|
| FastAPI | Yes (GuardQuote) |
| Prometheus + Grafana | Yes (home lab) |
| PostgreSQL | Yes (pi1) |
| PA-220 syslog | Yes (home lab) |
| rsyslog (pi0) | Yes |

---

## Research Questions

1. **Baseline vulnerability:** How much does accuracy degrade under FGSM and PGD attacks?
2. **Adversarial training effectiveness:** Does mixed clean/perturbed training improve robustness?
3. **Attack transferability:** Do adversarial examples transfer across model architectures?
4. **Feature-space constraints:** Can perturbations be constrained to valid network flows?
5. **Adversarial detection:** Can a secondary model detect perturbed inputs?

---

## Expected Results

| Metric | Target | Stretch |
|--------|--------|---------|
| Clean accuracy (multi-class) | >95% | >98% |
| Accuracy under FGSM (eps=0.05) | >85% | >90% |
| Accuracy under PGD (eps=0.05, 40 steps) | >75% | >85% |
| Adversarial training clean accuracy drop | <3% | <1% |
| Inference latency (Pi1, ONNX) | <50ms | <20ms |

---

## Timeline

| Week | Milestone |
|------|-----------|
| 1-2 | Data pipeline: download, preprocess, DataLoaders |
| 3-4 | Baseline models: SentinelNet, MLP, XGBoost, wandb |
| 5-6 | Adversarial attacks: FGSM, PGD, C&W implemented |
| 7-8 | Adversarial training: robust model, comparison |
| 9-10 | Deployment: ONNX, FastAPI, syslog consumer |
| 11-12 | Monitoring + writeup: Grafana, paper draft |
| 13+ | Stretch: LangChain agent, CVE RAG |

---

## Strategic Connections

| Context | Connection |
|---------|------------|
| **GuardQuote** | Shares FastAPI, MLflow, PostgreSQL, Docker patterns |
| **Home Lab** | Runs on Pi1, ingests PA-220 traffic, displays on Grafana |
| **Anthropic Fellowship** | Demonstrates PyTorch, adversarial ML, empirical research |
| **Layer 8** | Presentable research for club, forkable by members |
| **CTO Trajectory** | Research AND production systems capability |

---

## References

- Goodfellow et al. (2014). "Explaining and Harnessing Adversarial Examples" (FGSM)
- Madry et al. (2017). "Towards Deep Learning Models Resistant to Adversarial Attacks" (PGD)
- Carlini & Wagner (2017). "Towards Evaluating the Robustness of Neural Networks" (C&W)
- Sharafaldin et al. (2018). "Toward Generating a New Intrusion Detection Dataset" (CICIDS2017)
