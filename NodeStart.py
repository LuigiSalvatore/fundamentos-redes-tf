from Node import Node


def NodeStart():
    try:
        node = Node()
        print("Node started successfully.")
        main()
    except Exception as e:
        print(f"Error starting node: {e}")
        return None

def main():
    while True: