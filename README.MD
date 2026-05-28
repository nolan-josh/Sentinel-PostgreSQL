AUTHOR: [@nolan-josh ](https://github.com/nolan-josh)

This is a project designed to be a mulit agent chain of models used to detect, monitor and report back on security threats and provide real time alerts.

This project makes use of OpenAI_API, Langchain, MongoDB, Docker, redis, and qdrant. 

scripts/Data-Generator.py is used to create a mock dataset of cyber logs for a fake client. 

agents/agent.py is the main script for calling the langgraph nodes and running the agent. 

Current TO-DO:
- Have final node output a PDF document as a summary for every alert detected over the last X period. 
- If an alert is of a certain security level, determined by the agent, send a notification via teams, email, or other communication to alert the admin. 

© 2026 Josh Nolan. All rights reserved. No part of this code may be used, distributed, or modified without explicit permission
