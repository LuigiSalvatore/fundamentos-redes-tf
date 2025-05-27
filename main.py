import argparse
import Node
from NodeStart import NodeStart

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="Node")
	parser.add_argument("--name", required=True, help="Nome do dispositivo")
	parser.add_argument("--listen-port", required=True, help="Porta para o qual o dispositivo vai escutar mensagens")
	args = parser.parse_args()

node = Node.Node(args.name, int(args.listen_port))
NodeStart()