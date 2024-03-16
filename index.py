from antlr4 import *
from SolidityvulnerabilityLexer import SolidityvulnerabilityLexer
from SolidityvulnerabilityParser import SolidityvulnerabilityParser

class SolidityTimestampListener(ParseTreeListener):
    def enterTimestamp(self, ctx):
        print("Found timestamp:", ctx.getText())

def main():
    # Solidity code containing timestamps
    solidity_code = '''
      /*
 * @source: etherscan.io 
 * @author: -
 * @vulnerable_at_lines: 38
 */

pragma solidity ^0.4.19;

contract PrivateBank
{
    mapping (address => uint) public balances;
        
    uint public MinDeposit = 1ether;
    
    Log TransferLog;
    
    function PrivateBank(address _lib)
    {
        TransferLog = Log(_lib);
    }
    
    function Deposit()
    public
    payable
    {
        if(msg.value >= MinDeposit)
        {
            balances[msg.sender]+=msg.value;
            TransferLog.AddMessage(msg.sender,msg.value,"Deposit");
        }
    }
    
    function CashOut(uint _am)
    {
        if(_am<=balances[msg.sender])
        {            
            // <yes> <report> REENTRANCY
            if(msg.sender.call.value(_am)())
            {
                balances[msg.sender]-=_am;
                TransferLog.AddMessage(msg.sender,_am,"CashOut");
            }
        }
    }
    
    function() public payable{}    
    
}

contract Log 
{
   
    struct Message
    {
        address Sender;
        string  Data;
        uint Val;
        uint  Time;
    }
    
    Message[] public History;
    
    Message LastMsg;
    
    function AddMessage(address _adr,uint _val,string _data)
    public
    {
        LastMsg.Sender = _adr;
        LastMsg.Time = now;
        LastMsg.Val = _val;
        LastMsg.Data = _data;
        History.push(LastMsg);
    }
}
    '''

    # Create a lexer and parser
    lexer = SolidityvulnerabilityLexer(InputStream(solidity_code))
    stream = CommonTokenStream(lexer)
    parser = SolidityvulnerabilityParser(stream)

    # Parse the input
    tree = parser.sourceUnit()

    # Create a listener
    listener = SolidityTimestampListener()
    
    # Traverse the parse tree to find timestamps
    walker = ParseTreeWalker()
    walker.walk(listener, tree)

if __name__ == '__main__':
    main()
