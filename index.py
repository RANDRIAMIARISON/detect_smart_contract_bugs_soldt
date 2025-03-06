from antlr4 import *
from SolidityLexer import SolidityLexer
from SolidityParser import SolidityParser
from SolidityListener import SolidityListener
import sys

class SolidityVulnerabilityListener(SolidityListener):
    def __init__(self):
        self.vulnerabilities = []

    def enterBinaryOperation(self, ctx):
        operator = ctx.getChild(1).getText()
        if operator in ['+', '-', '*', '/', '%']:
            self.checkMathOperation(ctx)

    def checkMathOperation(self, ctx):
        parent_type = ctx.parentCtx.getChild(0).getSymbol().type
        if parent_type == SolidityParser.ExpressionContext and ctx.getChild(1).getText() == '/':
            self.reportVulnerability("Potential division operation, check for divide-by-zero.")

    def reportVulnerability(self, message):
        self.vulnerabilities.append(message)

def analyze_solidity_code(code):
    # Create an input stream from the Solidity code
    input_stream = InputStream(code)

    # Create a lexer and parser
    lexer = SolidityLexer(input_stream)
    token_stream = CommonTokenStream(lexer)
    parser = SolidityParser(token_stream)

    # Parse the code to get the AST
    tree = parser.sourceUnit()

    # Create a custom listener to perform vulnerability analysis
    listener = SolidityVulnerabilityListener()

    # Traverse the AST with the custom listener
    walker = ParseTreeWalker()
    walker.walk(listener, tree)

    # Return detected vulnerabilities
    return listener.vulnerabilities

# Example usage


def analyze_solidity_file(file_path):
    if not file_path.endswith(".sol"):
        print("Error: Please provide a Solidity (.sol) file.")
        return
    else:
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            print(content)

            vulnerabilities = analyze_solidity_code(content)
            
            if vulnerabilities:
                print("Detected vulnerabilities:")
                for vulnerability in vulnerabilities:
                    print(vulnerability)
            else:
                print("No vulnerabilities detected.")
            
        except FileNotFoundError:
            print(f"Error: The file '{file_path}' was not found.")
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <solidity_file.sol>")
    else:
        analyze_solidity_file(sys.argv[1])
