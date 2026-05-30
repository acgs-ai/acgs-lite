# Constitutions Examples

### Which template should I start from?

* If you are building tools to review, filter, or moderate user-generated content, start with the **Content Moderation Constitution** (`content_moderation.yaml`).
* If you are deploying automated customer support bots, virtual agents, or ticketing systems, start with the **Customer Service Constitution** (`customer_service.yaml`).
* If you are working on medical data processing, diagnostic aids, or healthcare communication workflows, start with the **Healthcare Constitution** (`healthcare.yaml`).
* If you are implementing AI tools for recruitment, resume screening, or automated employment assessments, start with the **Hiring & Recruitment Constitution** (`hiring.yaml`).
* If you are developing systems for automated credit decisioning, loan underwriting, alternative data cash flow scoring, or compliance-safe debt collection, start with the **Lending & Credit Constitution** (`lending.yaml`).

---

### Index of Available Templates

* **Content Moderation Constitution (`content_moderation.yaml`)**
  * **Domain:** Online platforms, Trust & Safety, and content compliance (EU DSA / US law).
  * **Description:** Governance rules for AI content moderation covering child safety, hate speech, violent extremism, misinformation, appeal processes, and transparency obligations.
  * **How to load:**
    ```python
    from acgs_lite import Constitution
    constitution = Constitution.from_yaml("examples/constitutions/content_moderation.yaml")
    ```

* **Customer Service Constitution (`customer_service.yaml`)**
  * **Domain:** Customer Support, Virtual Assistants, and Consumer Protection compliance (FTC Act / ADA).
  * **Description:** Governance rules for AI customer service agents covering PII protection, human escalation, commitment controls, complaint handling, response quality, and accessibility.
  * **How to load:**
    ```python
    from acgs_lite import Constitution
    constitution = Constitution.from_yaml("constitutions/customer_service.yaml")
    ```

* **Healthcare Constitution (`healthcare.yaml`)**
  * **Domain:** Clinical Decision Support, Patient Safety, and Health Data Privacy (HIPAA / FDA).
  * **Description:** Governance rules for AI systems used in clinical decision support, patient communication, diagnostics, medication management, emergency overrides, and health data processing.
  * **How to load:**
    ```python
    from acgs_lite import Constitution
    constitution = Constitution.from_yaml("constitutions/healthcare.yaml")
    ```

* **Hiring & Recruitment Constitution (`hiring.yaml`)**
  * **Domain:** HR tech, Recruitment, Bias Prevention, and Employment Law compliance (EEOC / Title VII / NYC LL 144).
  * **Description:** Governance rules for AI-assisted hiring, screening, and recruitment decisions covering bias prevention, transparency, adverse action compliance, and automated employment tools.
  * **How to load:**
    ```python
    from acgs_lite import Constitution
    constitution = Constitution.from_yaml("constitutions/hiring.yaml")
    ```

* **Lending & Credit Constitution (`lending.yaml`)**
  * **Domain:** Fintech, Credit Underwriting, Loan Origination, Model Governance, and Consumer Financial Protection (ECOA / FCRA / CFPB).
  * **Description:** Governance rules for AI-assisted lending, credit underwriting, alternative data risk management, loan pricing, and debt collection covering fair lending, redlining prevention, and adverse action compliance.
  * **How to load:**
    ```python
    from acgs_lite import Constitution
    constitution = Constitution.from_yaml("constitutions/lending.yaml")
    ```
