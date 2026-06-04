AUTHOR: [@nolan-josh ](https://github.com/nolan-josh)

This is a project designed to be a mulit agent chain of models used to detect, monitor and report back on security threats and provide real time alerts.

This project makes use of OpenAI_API, Langchain, PostgreSQL, Docker, redis, and qdrant. 

scripts/Data-Generator.py is used to create a mock dataset of cyber logs for a fake client. 
agents/agent.py is the main script for calling the langgraph nodes and running the agent. 

Current TO-DO: 
- Porting the project from MongoDB to PostgreSQL
- If an alert is of a certain security level, determined by the agent, send a notification via teams, email, or other communication to alert the admin. 
- Potentially create a basic dashboard that is a live view of the postgreSQL DB 

© 2026 Josh Nolan. All rights reserved. No part of this code may be used, distributed, or modified without explicit permission
