// ReadPtr.java — read the 8-byte pointer stored at each given address and report
// the function/symbol it targets. For resolving manual vtables / dispatch tables.
//   -postScript ReadPtr.java <hexaddr1> [hexaddr2] ...
// @category verimark
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;

public class ReadPtr extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        for (String s : args) {
            Address at = currentProgram.getAddressFactory().getAddress(s);
            String sect = "?";
            var block = currentProgram.getMemory().getBlock(at);
            if (block != null) sect = block.getName();
            long p;
            try { p = currentProgram.getMemory().getLong(at); }
            catch (Exception e) { println(s + " [" + sect + "]: unreadable"); continue; }
            Address tgt = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(p);
            Function f = currentProgram.getFunctionManager().getFunctionContaining(tgt);
            Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(tgt);
            println(String.format("%s [%s] -> 0x%x  %s%s", s, sect, p,
                f != null ? f.getName() : "(no func)",
                (f == null && sym != null) ? " sym=" + sym.getName() : ""));
        }
    }
}
