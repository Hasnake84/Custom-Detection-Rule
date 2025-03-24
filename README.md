# Custom-Detection-Rule

---

## Scenario: Suspected Malware Infiltration in a Financial Institution

A large financial institution has a hybrid cloud infrastructure with critical workloads hosted in Azure. As part of the organization's cybersecurity strategy, they have implemented Microsoft Defender for Endpoint (EDR) to protect their endpoints and Microsoft Sentinel for centralized threat detection and analysis. Recently, an employee in the Finance Department reported unusual activity on their endpoint, including the appearance of a suspicious PowerShell script running background tasks.
Objective:
The organization's security team has decided to simulate a malware attack (EICAR test file) to evaluate the effectiveness of Microsoft Defender for Endpoint and Sentinel in detecting and responding to such threats. 

## Objectives
- Create and implement a custom detection rule in Microsoft Sentinel and Defender for Endpoint to detect specific PowerShell commands such as "Execution PolicyBypass  and Invoke-WebRequest.
- Confirm that Sentinel and Defender for Endpoint successfully detects the suspicious activity.
- Verify that Sentinel collects and correlates the logs to generate actionable alerts.
---

### **Tools and Resources**  
- **Azure Virtual Machine** (Windows11)  
- **Microsoft Defender for Endpoint (EDR)** enabled and configured  
- **Microsoft Sentinel** for log aggregation and analysis  
- **EICAR Test File** (Safe and harmless malware simulation)  

---

### Prepare the Environment 
 **Set Up an Azure Virtual Machine (VM):**
   - Launch an Azure VM with Windows OS.
   - Ensure the VM has proper network security group (NSG) rules for remote access.  

 **Enable Microsoft Defender for Endpoint (EDR):**
   - Install and configure the Defender agent on the VM.
   - Verify that real-time protection is active.
 
 **Integrate the VM with Microsoft Sentinel:**
   - Connect Defender to Microsoft Sentinel using the **Log Analytics Workspace** for centralized log collection and monitoring.

 ### Create Alert Rule in Microsoft Sentinel:
      - Sentinel > Analytics > Scheduled Query Rule > Create Alert Rule
       - Rule Name: PowerShell Suspicious Web Request 🚩
       - Description: Detects PowerShell malicious executions 📥.
   #### KQL Query
      DeviceProcessEvents
      | where DeviceName == TargetDevice
      | where FileName == "powershell.exe"
      | where ProcessCommandLine has_all ("ExecutionPolicy Bypass", "Invoke-WebRequest")
      | where InitiatingProcessAccountName != "system"
 
<a href="https://imgur.com/zK3FnfW"><img src="https://i.imgur.com//zK3FnfW.png" tB2TqFcLitle="source: imgur.com" /></a>
   
### Create a Custom Detection Rule on Defender for Endpoint
Defender for Endpoint > Hunting > Advanced Hunting > in the query editor window:
   #### KQL Query
     let target_machine = "hewindows";
     DeviceNetworkEvents  
     | where DeviceName == target_machine
     | where InitiatingProcessCommandLine has_all ("ExecutionPolicy Bypass", "Invoke-WebRequest")
     | where InitiatingProcessAccountName != "system"

 ### Simulate the Malware Incident by downloading the EICAR Test File:  
   - Run the following command in PowerShell to safely simulate a malware attack:  
     ```powershell
     powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://secure.eicar.org/eicar.com.txt -OutFile C:\test\eicar.com
     ```
     _Note: The EICAR test file is specifically designed for antivirus testing and poses no actual harm._

 <a href="https://imgur.com/w1nOHRr"><img src="https://i.imgur.com//w1nOHRr.png" tB2TqFcLitle="source: imgur.com" /></a>

2. **Trigger Detection**:
   - Downloading the EICAR file on the VM. Defender for Endpoint should trigger an alert for **Suspicious file**
   - Test the rule by executing PowerShell commands on the VM and ensure the rule fires correctly in Sentinel.

<a href="https://imgur.com/12TDERC"><img src="https://i.imgur.com//12TDERC.png" tB2TqFcLitle="source: imgur.com" /></a>

3. **Monitor Alerts**:  
   - Log into Microsoft Sentinel.
   - Query logs and review alerts triggered by the Defender for Endpoint agent.

<a href="https://imgur.com/9CVzbaL"><img src="https://i.imgur.com//9CVzbaL.png" tB2TqFcLitle="source: imgur.com" /></a>

---

### **Step 3: Investigate the Incident**  
1. **Analyze the Alert in Microsoft Sentinel**:  
   - Use **KQL queries** to locate and analyze logs related to the alert.
   
     SecurityAlert
     | where AlertName == "Malware detected in file"
     | project AlertName, TimeGenerated, Description, EntityDetails
     ```

2. **Review Endpoint Activity in Defender (EDR)**:  
   - Investigate the process tree to understand how the file was executed and whether it interacted with other system components.  
   - Examine disk and memory operations logged by the EDR agent.

3. **Assess the Impact**:  
   - Determine if the test file attempted lateral movement or caused further system changes.
   - Check network logs in Sentinel for suspicious traffic generated by the file.

---

### **Step 4: Contain and Resolve the Incident**  
1. **Contain the Threat**:  
   - Verify that Defender for Endpoint automatically quarantined the EICAR test file.  
   - Check system logs to ensure no additional files were affected.

2. **Perform Remediation**:  
   - Delete the EICAR test file from the system.  
   - Run a full system scan using the Defender agent to ensure the endpoint is clean.

3. **Document Actions Taken**:  
   - Note the remediation steps, including log review and manual deletion of the file.

---

### **Step 5: Review and Report**  
1. **Create a Post-Incident Summary Report**:  
   - Document the process, including:
     - **Detection**: Alerts generated by Defender and logs in Sentinel.
     - **Investigation**: Process tree analysis and log details.
     - **Remediation**: Actions taken to resolve the issue.  

2. **Publish the Documentation**:  
   - Format the report for professional sharing, emphasizing the practical use of Sentinel and EDR for threat hunting and incident response.

---

### **Final Notes**  
By relying on Microsoft Sentinel and Microsoft Defender for Endpoint (EDR), this simulation showcases effective detection, investigation, and remediation workflows in the absence of Microsoft 365 Defender. Regular incident simulations help strengthen your technical capabilities and prepare for real-world scenarios.

---


