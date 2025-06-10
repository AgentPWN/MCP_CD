# Import smolagents 
from smolagents import ToolCallingAgent, ToolCollection, LiteLLMModel
# Bring in MCP Client Side libraries
from mcp import StdioServerParameters
import sys

def main():
    print("Setting up agent connection...")
    
    # Specify Ollama LLM via LiteLLM
    model = LiteLLMModel(
            model_id="ollama_chat/gemma3:latest",
            num_ctx=8192) 

    # Outline STDIO stuff to get to MCP Tools
    server_parameters = StdioServerParameters(
        command="uv",
        args=["run", "mcp-cd.py", "--port", "5433"],
        env=None,
    )

    # Run the agent using the MCP tools 
    try:
        with ToolCollection.from_mcp(server_parameters, trust_remote_code=True) as tool_collection:
            agent = ToolCallingAgent(tools=[*tool_collection.tools], model=model)
            
            print("✅ Agent ready! Type your queries below.")
            print("Type 'quit', 'exit', or 'q' to exit.")
            print("-" * 50)
            
            while True:
                try:
                    # Get user input
                    user_input = input("\n🤖 Enter your query: ").strip()
                    
                    # Check for exit commands
                    if user_input.lower() in ['quit', 'exit', 'q', '']:
                        print("👋 Goodbye!")
                        break
                    
                    # Run the query
                    print("\n🔄 Processing...")
                    response = agent.run(user_input)

                    print(f"\n📊 Response:\n{response}")
                    print("-" * 50)
                    
                except KeyboardInterrupt:
                    print("\n\n👋 Interrupted by user. Goodbye!")
                    break
                except Exception as e:
                    print(f"\n❌ Error processing query: {e}")
                    print("Try again with a different query.")
                    continue
                    
    except Exception as e:
        print(f"❌ Failed to setup agent connection: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()


    
# agent.run("Tell me the account whose asset status is complete in hackerview scans.")
# agent.run("What are the ids of people who forgot their passwords")
# agent.run("give me all the data from forget password")
# agent.run("give me all the data from hackerview scan status")
# agent.run("find all the emails")
# agent.run("There are two tables. One is called user, it has a column called email. The other is a table called otp_data. It has a column called new_email. Find all the emails in the users table that are not in the otp_data table and end with gmail.com.")  
# agent.run("Tell me which account does the most amount of scans and which account does the least amount of scans. Also, tell me the number of scans for each account.")
# agent.run("Can you tell me at which hour do most users login?")
# agent.run("Do more users change passwords in the morning or in the evening? Please provide the number of users for each time period. the login time field looks like this: '2023-07-18 06:46:44.424376'. Morning is from 6 AM to 12 PM, evening is from 12 PM to 6 PM. Please provide the number of users for each time period.")
