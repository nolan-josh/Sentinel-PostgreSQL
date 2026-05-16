import time, os
from pymongo import MongoClient
from langchain_openai import ChatOpenAI
from langchain.agents import create_agent
from langchain_core.tools import tool
from langchain_core.messages import  BaseMessage, ToolMessage, SystemMessage, AIMessage
from langgraph.graph.message import add_messages
import json
from langgraph.prebuilt import ToolNode
from typing import Dict, TypedDict, List
from langgraph.graph import StateGraph, START, END
from io import BytesIO
from PIL import Image
from typing import Annotated, Dict, TypedDict, List, Sequence


def print_stream(stream):
    for s in stream:
        message = s["messages"][-1]
        if isinstance(message, tuple):
            print(message)
        else:
            message.pretty_print()
            

mongo_URL = os.getenv("MONGO_URI", "mongodb://localhost:27017/?replicaSet=rs0&directConnection=true")

db = MongoClient(mongo_URL)["sentinel_ai"]        
logs_collection = db['logs']
alerts_collection = db['alerts'] # (alerts collection is created first time we populate it)
MALICIOUS_IPS = [
    "185.220.101.45",  
    "45.33.32.156",
    "198.20.69.74",
    "89.248.167.131",
]
     
@tool
def get_IP_info(IP: str):
    """A method used to query the mongoDB and return more info for entries with that same IP address."""
    pipeline = [{ "$match": { "source_ip": IP } },]
    documents = logs_collection.aggregate(pipeline) 
    
    data = []
    for document in documents:
        data.append(document)
    return data

tools = [get_IP_info]

def listen(graph: StateGraph):
    connected = False
    app = graph.compile()
    print("graph compiled!")
    #  compile graph

    while not connected:
        try:     
            print("Listening...")
            with alerts_collection.watch() as changes:
                        for change in changes:
                            print(f'change found: {change['fullDocument']}')
                            print(f"\n {str(change['fullDocument'])}")
                            try:
                                ## invoke graph
                                inputs = {"messages": 
                                    [(
                                        "user", 
                                        f"We have detected a new entry in our alerts collection within our database. Using the data below please determine if the severity needs to be escelated based on thise source_ip's existing history in the database. data is here: {str(change['fullDocument'])}")]}
                                print_stream(app.stream(inputs, stream_mode="values"))
                                return
                            except Exception as error:
                                print(f"error in calling agent: {str(error)}")
                        
                    ## here we call agent to when it finds as change
                    ## triage agent will check the format matches what we are used to seeing and nothing important is null
                    
                    
        except Exception as e:
            print(f"MongoDB not ready, retrying in 3 seconds... ({e})")
            time.sleep(3)
    
# create state
# decribes attributes about request
# starts blank    
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
      

## agent state created above is not a class isntance, becuase it inherits from typedict it is just saying a dictionary with the name agentState should contain messages
# our expcted return type AgentState is met when we return a dict containg messages
def model_call(state: AgentState) -> AgentState:
    system_prompt = SystemMessage(content="you are an ai assistant in my cyber security team working with a SOC system, answer my query to the best of your ability please")
    response = model.invoke([system_prompt] + state["messages"])
    return {"messages": [response]}



def should_LLM_call_tool(state: AgentState):
    messages = state["messages"]
    last_message = messages[-1]
    
    # if the last message doesnt contain the type tool_calls that we imported above 
    # an Ai message in langchain can contain: AIMessage(content="...", tool_calls=[...])
    if not last_message.tool_calls:
        return "end"
    else:
        return "call_tool"
    
model = ChatOpenAI(model="gpt-4o").bind_tools(tools)
graph = StateGraph(AgentState)
graph.add_node("agent", model_call)

# model can make tool call because we did .bind at the start so can use shouldcotinue to check if model
# is trying to call a tool or not 
# if it is we go tot ool
tool_node = ToolNode(tools)
print(type(tool_node))
graph.add_node("tools", tool_node)



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
        "end": END,
    }
)


## after calling tool go back to agent so its ongoing 
graph.add_edge("tools", "agent")

def main():
    listen(graph=graph)


if __name__ == "__main__":
    main()



