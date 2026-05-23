import time, os, requests
from pymongo import MongoClient
from pydantic import BaseModel
from langchain_openai import ChatOpenAI
from langchain.agents import create_agent
from langchain_core.tools import tool
from langchain_core.messages import  BaseMessage, ToolMessage, SystemMessage, AIMessage, HumanMessage
from langgraph.graph.message import add_messages
import json
from langgraph.prebuilt import ToolNode
from typing import Dict, TypedDict, List
from langgraph.graph import StateGraph, START, END
from io import BytesIO
from PIL import Image
from typing import Annotated, Dict, TypedDict, List, Sequence
from bson import ObjectId
import dotenv
import operator
import redis


dotenv.load_dotenv()

mongo_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017/?replicaSet=rs0&directConnection=true")

db = MongoClient(mongo_URL)["sentinel_ai"]        
logs_collection = db['logs']
alerts_collection = db['alerts'] 
MALICIOUS_IPS = [
    "185.220.101.45",  
    "45.33.32.156",
    "198.20.69.74",
    "89.248.167.131",
]

 
class AgentState(TypedDict):
    """the add_message is an import above that appends the state instead of overwriting

    Args:
        TypedDict (_type_): _description_
        
    BaseMessages : 
    
        Messages are the inputs and outputs of a chat model.

        Examples include [`HumanMessage`][langchain.messages.HumanMessage],
        [`AIMessage`][langchain.messages.AIMessage], and
        [`SystemMessage`][langchain.messages.SystemMessage].
    """
    messages: Annotated[Sequence[BaseMessage], add_messages]
    suspect_IP: str
    alert_ID: ObjectId
    IP_info: dict 
    alert_type: str
    affected_host: str                                    
    username: str
    watchlist:  Annotated[list[str], operator.add]
    blocked: Annotated[list[str], operator.add]
    action_decision: str
    # we need a reducer here for adding becasue if we just did state["watchlist"] = state["watchlist"] + new_list_data_to_add then
    # when two nodes run in parallel and both try to update watchlist at the same time — LangGraph doesn't know how to 
    # merge two different versions of the list, so one overwrites the other and you lose data.
    # operator.add as a reducer tells LangGraph explicitly "when two nodes both update this field, combine them by concatenating" — 
    # solving the parallel update problem.
      

def print_stream(stream):
    for s in stream:
        message = s["messages"][-1]
        if isinstance(message, tuple):
            print(message)
        else:
            message.pretty_print()
            

     
@tool
def get_IP_info(IP: str):
    """A method used to query the mongoDB and return more info for entries with that same IP address."""
    pipeline = [
        { "$match": { "source_ip": IP } },
        { "$sort": { "timestamp": -1}},
        { "$limit": 5},] # last 5 results to reduce token costs
    documents = logs_collection.aggregate(pipeline) 
    
    data = []
    for document in documents:
        data.append(document)
    return data


@tool
def escalate_alert_entry(id: str, new_severity: str):
    """A method that is used to elevate the severity of a db entry in the alerts collection in the mongoDB database
_

    Args:
        id (str): The _id from the mongoDB entry that requires escalting. the _id is unique to each entry in the collection
        new_severity (str): The new severity that the entry in thje collection should be updated to have

    Returns:
        True if it worked else False
    """
    try:
        alerts_collection.update_one(
            {"_id": ObjectId(id)},
            {"$set": {"severities": new_severity}}
        )
        return f"{True} for _id: {ObjectId(id)}"
    except Exception as e:
        print("error")
        return False
        
    
    
def listen(graph: StateGraph):
    app = graph.compile()
    print("graph compiled!")
    while True:
        try:     
            print("Listening...")
            with alerts_collection.watch() as changes:
                        time.sleep(10)
                        for change in changes:
                            alert = change['fullDocument']
                            print(f'change found: {change['fullDocument']}')
                            # print(f"\n {str(change['fullDocument'])}")
                            try:
                                inputs = {
                                    "messages": [(
                                        "user", 
                                        f"""We have detected a new entry in our alerts collection within our database. 
                                        Using the data below please determine if the severity needs to be escelated based on thise source_ip's existing history in the database. 
                                        Data is here: {str(change['fullDocument'])} Once you have made your decision based on then data you pulled from the db for that IP, 
                                        please update the entry in my collection to the more appropriate severity.""")],
                                    
                                    "suspect_IP": alert.get("source_ip", ""),
                                    "alert_ID": alert.get("_id", ""),
                                    "alert_type": alert.get("type", ""),
                                    "affected_host": alert.get("affected_host", ""),
                                    "username": alert.get("username", "")
                                }
                                print(f"initial state: {inputs}")
                                print_stream(app.stream(inputs, stream_mode="values"))
                                return
                            except Exception as error:
                                print(f"error in calling agent: {str(error)}")
                        
                    ## here we call agent to when it finds as change
                    ## triage agent will check the format matches what we are used to seeing and nothing important is null
                    
                    
        except Exception as e:
            print(f"MongoDB not ready, retrying in 3 seconds... ({e})")
            time.sleep(3)
    


## agent state created above is not a class isntance, becuase it inherits from typedict it is just saying a dictionary with the name agentState should contain messages
# our expcted return type AgentState is met when we return a dict containg messages
def model_call(state: AgentState) -> AgentState:
    system_prompt = SystemMessage(content="you are an ai assistant in my cyber security team working with a SOC system, answer my query to the best of your ability please")
    response = model.invoke([system_prompt] + state["messages"])
    
     # extract IP from tool calls if the agent called get_IP_info
    suspect_ip = state.get("suspect_IP", "")  # keep existing if already set
    
    if response.tool_calls:
        for tool_call in response.tool_calls:
            if tool_call["name"] == "get_IP_info":
                suspect_ip = tool_call["args"]["IP"]
                
    return {
        "messages": [response],
        "suspect_IP": suspect_ip  # write IP to state
    }

def should_LLM_call_tool(state: AgentState):
    messages = state["messages"]
    last_message = messages[-1]
    
    # if the last message doesnt contain the type tool_calls that we imported above 
    # an Ai message in langchain can contain: AIMessage(content="...", tool_calls=[...])
    if not last_message.tool_calls:
        return "dont_call_tool"
    else:
        return "call_tool"
    

def call_abuseipdb(IP_to_check: str): 
    """This method takes an IP address as as string and uses an API to fetch data from an IP database to learn more about this IP address.
    We will be returned information in a JSON format and it allows us to gain more context about this IP.

    Returns:
        data: The JSON formatted string containing information surrounding this IP address.
    """
    api_key = os.getenv("ABUSE_IPDB_KEY")
    
    # Defining the api-endpoint
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': IP_to_check,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': str(api_key)
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)

    # Formatted output
    decodedResponse = json.loads(response.text)
    data = json.dumps(decodedResponse["data"], sort_keys=True, indent=4)
    print(f"data: {data}")
    return data
    
def call_virustotal(IP_to_check: str):
    API_KEY = os.getenv("VIRUS_TOTAL_KEY")    

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{IP_to_check}"

   
    headers = {
        "x-apikey": API_KEY,
        "accept": "application/json"
    }
    
    response = json.loads(requests.get(url, headers=headers).text)
    response.update({"ip_address": IP_to_check}) ## appends the IP to end of response so we know which IP this data maps to
    print(json.dumps(response, sort_keys=True, indent=4))

def threat_intel_node(state: AgentState) -> AgentState:
    ip = state["suspect_IP"]

    # call AbuseIPDB
    abuse_result = call_abuseipdb(ip)

    # call VirusTotal  
    vt_result = call_virustotal(ip)

    # langhcain handles a partial dict and will merge this into our state: AgentState dict
    return {
        "IP_info": {
            "abuseipdb": abuse_result,
            "virustotal": vt_result
        }
    }   

class AnswerWithJustification(BaseModel):
    '''An answer to the user question along with justification for the answer.'''

    answer: str
    justification: str

def log_analyse_node(state: AgentState) -> AgentState:
    
    ## check the state and decide if we need to block it
    # update action_decision based on this
    system_prompt = SystemMessage(content="you are an ai assistant in my cyber security team working with a SOC system, using the state answer my question to the best of your ability")
    new_human_prompt = HumanMessage(content=f"""
        Based on the following information, determine if the suspect IP should be 
        added to watchlist, blocklist, or do nothing. Make the answer section of the output just be the word of the action you choose.
        Suspect IP: {state["suspect_IP"]}
        Alert type: {state["alert_type"]}
        IP reputation data: {state["IP_info"]}
    """)
    structured_model = model.with_structured_output(AnswerWithJustification)
    response = structured_model.invoke([system_prompt] + state["messages"] + [new_human_prompt])
    print(f"\n\n answer: {response.answer}")
    return(state)

    



tools = [get_IP_info, escalate_alert_entry]
model = ChatOpenAI(model="gpt-4o").bind_tools(tools)

def create_graph() -> StateGraph:
    
    
    graph = StateGraph(AgentState)
    graph.add_node("agent", model_call)

    # model can make tool call because we did .bind at the start so can use shouldcotinue to check if model
    # is trying to call a tool or not 
    # if it is we go tot ool
    tool_node = ToolNode(tools)
    print(type(tool_node))
    graph.add_node("tools", tool_node)
    graph.add_node("threat_intel_node", threat_intel_node)
    graph.add_node("analysis_node", log_analyse_node)


    # the model knows to call the right tool in toolnode because it looks at last message 
    # it gets last message from agentstat that was passed when we crated graph = StateGraph(AgentState)
    # it then comparesa the toolcall in the AI's last message to the tools in our tools[] to find the tool it wants to call
    # it then uses the args outlined in the AI's last message
    #   NOTE: (The AI knows what args to pass each tool since when we do bind tools it looks at the schema for each method / tool that it's passed)

    graph.set_entry_point("agent")
    graph.add_conditional_edges(
        "agent",
        should_LLM_call_tool,
        {
            "call_tool": "tools",
            "dont_call_tool": "threat_intel_node",
        }
    )
    graph.add_edge("tools", "agent")
    graph.add_edge("threat_intel_node", "analysis_node")
    graph.add_edge("analysis_node", END)
    

    ## after calling tool go back to agent so its ongoing 
    return graph

def main():
    # graph = create_graph()
    # listen(graph=graph)
    
    
    # should be using sadd for redis set not list, we just need a set of IPs not a list
    client = redis.Redis(host="localhost", port=6379, decode_responses=True)
    client.delete("myset")
    res1 = client.sadd("myset", "josh", "tom")
    students = client.smembers("myset")
    print(students)  # >>> 2


if __name__ == "__main__":
    main()



