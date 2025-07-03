# Connection-Events

It processes EVTX files to extract connection events, specifically 1149, 21, 23, 24, and 131 EIDs.
Basically all connection elements besides 4624. The logic is in there for 4624 but I haven't found an efficient way of searching Security EVTX, it takes ages.

For every event hit, the script outputs a row in a CSV timeline, including:
Date/Time - **yyyy-MM-ddTHH:mm:ssZ**
Evidence Source - includes the log source and Event ID (e.g **LocalSessionManager - EID 21**)
Activity Description - shows the username and IP address with context (e.g **RDP connection with jack from 10.1.2.3**)
User - extracts the username
Details/Comments - includes the RDP Session ID
