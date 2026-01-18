+++
title = "Penetration Test: Pre-Engagement Template"
+++

# Penetration Test: Pre-Engagement Template

---

## 1. Project Metadata

- **Client Name:** `[Client Name]`
- **Project Name:** `[Project Name / Engagement Title]`
- **Date Created:** `[YYYY-MM-DD]`
- **Start Date:** `[YYYY-MM-DD]`
- **End Date:** `[YYYY-MM-DD]`

### Key Personnel

- **Primary Client Contact:** `[Name, Title, Email, Phone]`
- **Secondary Client Contact:** `[Name, Title, Email, Phone]`
- **Technical Support Contact:** `[Name, Title, Email, Phone]`
- **Signatory Authority:** `[Name, Title]`
- **Lead Penetration Tester:** `[Your Name]`

---

## 2. Master Document Checklist

- [ ] **1. Non-Disclosure Agreement (NDA)**
  > - **Status:** `[Pending | Signed]`
  > - **Notes:** 

- [ ] **2. Scoping Questionnaire**
  > - **Status:** `[Sent | Received | Reviewed]`
  > - **Notes:** 

- [ ] **3. Scoping Document**
  > - **Status:** `[Drafting | Finalized]`
  > - **Notes:** 

- [ ] **4. Penetration Testing Proposal (Contract/SoW)**
  > - **Status:** `[Drafting | Sent | Signed]`
  > - **Notes:** 

- [ ] **5. Rules of Engagement (RoE)**
  > - **Status:** `[Drafting | Finalized | Signed]`
  > - **Notes:** 

- [ ] **6. Contractors Agreement (Physical Assessments)**
  > - **Status:** `[N/A | Required | Signed]`
  > - **Notes:** 

- [ ] **7. Reports**
  > - **Status:** `[In Progress | Delivered]`
  > - **Notes:** 

---

## 3. Scoping Questionnaire

### Assessment Type(s) Required

- [ ] Internal Vulnerability Assessment
- [ ] External Vulnerability Assessment
- [ ] Internal Penetration Test
- [ ] External Penetration Test
- [ ] Wireless Security Assessment
- [ ] Application Security Assessment
- [ ] Physical Security Assessment
- [ ] Social Engineering Assessment
- [ ] Red Team Assessment
- [ ] Web Application Security Assessment

> **Notes on specific requirements (e.g., black box, evasiveness, vishing):**
> 

### Critical Scoping Information

- **How many expected live hosts?**
  > **Answer:** 
- **How many IPs/CIDR ranges in scope?**
  > **Answer:** 
- **How many Domains/Subdomains are in scope?**
  > **Answer:** 
- **How many wireless SSIDs in scope?**
  > **Answer:** 
- **How many web/mobile applications? Authenticated roles?**
  > **Answer:** 
- **For phishing: how many users targeted? List provided?**
  > **Answer:** 
- **For physical assessment: how many locations? Geographically dispersed?**
  > **Answer:** 
- **Objective of the Red Team Assessment? Out of scope activities?**
  > **Answer:** 
- **Is a separate Active Directory Security Assessment desired?**
  > **Answer:** 
- **Will network testing be anonymous or as a standard domain user?**
  > **Answer:** 
- **Do we need to bypass Network Access Control (NAC)?**
  > **Answer:** 

### Information Disclosure & Evasiveness

- **Information Disclosure Level:**
  - [ ] **Black Box** (no information provided)
  - [ ] **Grey Box** (IPs/URLs provided)
  - [ ] **White Box** (detailed information provided)

- **Evasiveness Level:**
  - [ ] **Non-Evasive**
  - [ ] **Hybrid-Evasive** (start quiet, get louder)
  - [ ] **Fully Evasive**

---

## 4. Contract / Scope of Work (SoW) Checklist

- [ ] **NDA:**
  > - A secrecy contract between the client and contractor.
  > - **Notes:** 

- [ ] **Goals:**
  > - High-level and fine-grained milestones to be achieved.
  > - **Notes:** 

- [ ] **Scope:**
  > - Individual components to be tested (domains, IPs, specific accounts).
  > - **Notes:** 

- [ ] **Penetration Testing Type:**
  > - The chosen type of test (e.g., Internal, External, Web App).
  > - **Notes:** 

- [ ] **Methodologies:**
  > - Examples: OSSTMM, OWASP, PTES.
  > - **Notes:** 

- [ ] **Penetration Testing Locations:**
  > - External (Remote via VPN) and/or Internal.
  > - **Notes:** 

- [ ] **Time Estimation:**
  > - Start and end dates for the entire engagement and for specific phases (Exploitation, Post-Ex). Testing hours (during/after business hours).
  > - **Notes:** 

- [ ] **Third Parties:**
  > - Any cloud providers, ISPs, or hosting providers involved. Written consent must be obtained from them by the client.
  > - **Notes:** 

- [ ] **Evasive Testing:**
  > - Clarify if techniques to evade security systems are in scope.
  > - **Notes:** 

- [ ] **Risks:**
  > - Inform the client of potential risks (e.g., system instability, locked accounts).
  > - **Notes:** 

- [ ] **Scope Limitations & Restrictions:**
  > - Which servers, workstations, or network components are critical and must be avoided.
  > - **Notes:** 

- [ ] **Information Handling:**
  > - Compliance requirements (e.g., HIPAA, PCI, NIST).
  > - **Notes:** 

- [ ] **Contact Information:**
  > - A full list of contacts and an escalation priority order.
  > - **Notes:** 

- [ ] **Lines of Communication:**
  > - E-mail, phone calls, personal meetings.
  > - **Notes:** 

- [ ] **Reporting:**
  > - Structure of the report, customer-specific requirements, and presentation plans.
  > - **Notes:** 

- [ ] **Payment Terms:**
  > - Prices and terms of payment.
  > - **Notes:** 

---

## 5. Rules of Engagement (RoE) Checklist

- [ ] **Introduction:** Description of the RoE document.
- [ ] **Contractor:** Company name, key contacts.
- [ ] **Penetration Testers:** Names of testers.
- [ ] **Contact Information:** Full contact details for all parties.
- [ ] **Purpose:** Purpose of the penetration test.
- [ ] **Goals:** Goals to be achieved.
- [ ] **Scope:** All IPs, domains, URLs, CIDR ranges.
- [ ] **Lines of Communication:** E-mail, phone, etc.
- [ ] **Time Estimation:** Start and end dates.
- [ ] **Time of the Day to Test:** Specific testing hours.
- [ ] **Penetration Testing Type:** The specific type of test.
- [ ] **Penetration Testing Locations:** How the connection to the client network is established.
- [ ] **Methodologies:** OSSTMM, PTES, OWASP, etc.
- [ ] **Objectives / Flags:** Specific users, files, or information to target.
- [ ] **Evidence Handling:** Encryption and secure protocols for handling evidence.
- [ ] **System Backups:** Acknowledgment of client's backup procedures.
- [ ] **Information Handling:** Strong data encryption requirements.
- [ ] **Incident Handling and Reporting:** Process for emergency contact and test interruptions.
- [ ] **Status Meetings:** Frequency, dates, times, and attendees.
- [ ] **Reporting:** Type, target readers, and focus of the final report.
- [ ] **Retesting:** Start and end dates for retesting patched vulnerabilities.
- [ ] **Disclaimers and Limitation of Liability:** System damage, data loss.
- [ ] **Permission to Test:** Confirmation of signed contract.

---

## 6. Kick-Off Meeting Agenda

- **Attendees:**
  - `[List of Client POCs]`
  - `[List of Client Technical Staff]`
  - `[List of Pentesting Team Members]`
- **Agenda Items:**
  - [ ] Review nature and scope of the penetration test.
  - [ ] Confirm Rules of Engagement (RoE).
  - [ ] Define "Critical Vulnerability" and the process for immediate notification (e.g., for unauthenticated RCE).
  - [ ] Discuss potential risks (log entries, alarms, accidental account lockouts).
  - [ ] Explain the full penetration testing process in a clear, non-technical way.
  - [ ] Confirm client's goals and priorities.
  - [ ] Open floor for Q&A.

---

## 7. Physical Assessment Addendum

- [ ] **Introduction**
- [ ] **Contractor**
- [ ] **Purpose**
- [ ] **Goal**
- [ ] **Penetration Testers**
- [ ] **Contact Information**
- [ ] **Physical Addresses**
- [ ] **Building Name**
- [ ] **Floors**
- [ ] **Physical Room Identifications**
- [ ] **Physical Components**
- [ ] **Timeline**
- [ ] **Notarization**
- [ ] **Permission to Test ("Get Out of Jail Free Card")**
