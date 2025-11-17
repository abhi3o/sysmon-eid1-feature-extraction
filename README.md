Extracting features from Sysmon Event ID 1 (Process Create) logs to classify processes as anomalous or benign to support research in behavioral detection and early-stage anomaly identification.

Description of extracted features:
**Feature 1**: The first feature we extract is the parent of the process from the parent executable. For any given child process, in a normal environment, the parent is a single process which usually spawns the same child. Since this is a categorical feature, we utilise the one-hot encoded values of the parent.

**Feature 2**: Here, we use Term Frequency-Inverse Document Frequency (TF-IDF) featurizer to obtain features generated from the word description of the process. Description contains an additional information about the process executable, and it is oservered that it is only written by reputable software vendors for their software.

**Feature 3**: For the same reason as above, the next feature we obtain is either true or false depending on the description, if it exists or not.

**Feature 4**: Here, we set the feature as either true if the process executable is a Living-off-the-Land Binary ("LoLBin"). The term "LoLBin" has been used more or less loosely to refer to any Microsoft-signed binary included in the default Windows installation. The literature suggests that LoLBins are a preferred method for APTs and other organized threat actors.

**Feature 5**: To obtain this feature, we analyse the process executable path. If the executable is from a non-standard Windows path, we set the feature as true, else false. This is because malicious binaries are usually dropped to unusual locations by threat actors or attackers for later use.

**Feature 6**: Threat actors or attackers change the directory to a custom location to access their dropped programs, malicious or not, before utilising them. Current directory of the process, therefore, provides an idea about the malicious nature of the process executable. In this feature, we set true if the current working directory is a non-standard Windows path.

**Feature 7**: In this feature, we check if the process is running with elevated privileges. Higher privileges do not necessarily mean that a process is malicious, but given the nature of machine learning, the model assigns an appropriate weight to a feature, which is proportional to its contribution in classification.

**Feature 8**: Here, we set the feature as true if the parent is a not a system program. A custom program might be used to spawn a process, system or third-party, to perform an anomalous action.

**Feature 9**: In this feature, we keep the value as true, if the process command line contains an IPv4 address. An IP address itself is not malicious, but an attacker uses an IP address for establishing a connection to their command and control infrastructure. A threat actor or an attacker generally use an IP address instead of domain names to reduce attack traceability and cost.

**Feature 10**: For this feature, we check if the process executable path matches the path in the process command line. A mismatch indicates that the process is malicious in nature. 

**Feature 11**: This feature is a percentile score between 0 to 1 depending upon the familiarity of a parent-child pair. In a normal environment, it is generally observed that, more often than not, a child process is spawned through the same parent. For example, an event of cmd.exe spawning a winword.exe process might be acceptable in some cases, but a winword.exe process spawning a cmd.exe process is likely an indicator of suspicious activity.

**Feature 12**: This feature is a boolean value, as a result of the process commandline containing a PowerShell Script (.ps1), or a Virtual Basic Script (.vbs), or a Batch File (.bat), or a Dynamic Link Library (.dll). Commands with scripts indicate that the process is launched as a result of executing an external program or a custom code.

**Feature 13**: In this feature, we set the value as true if the process commandline consists of a connection to web server (http and https), or a file server (ftp). For delivery of exploits, it is observed that the threat actor uses LoLBins like certutil.exe, certreq.exe, cmd.exe, ftp.exe, winget.exe, powershell.exe, etc.

**Feature 14**: To extract this feature, we check if the process commandline consists of a network path (e.g. //192.168.1.101). In a already compromised system, the threat actor wants to access the systems in the local network, put or download exploits in/from those systems.
