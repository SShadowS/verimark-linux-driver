// DumpCallers.java — decompile every function that CALLS the function containing
// each given address (to find who selects/drives a helper).
//   -postScript DumpCallers.java <outdir> <hexaddr1> [hexaddr2] ...
// @category verimark
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import java.io.*;
import java.util.*;

public class DumpCallers extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) { println("usage: DumpCallers <outdir> <addr>..."); return; }
        File outdir = new File(args[0]); outdir.mkdirs();
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        Set<Function> callers = new LinkedHashSet<>();
        for (int i = 1; i < args.length; i++) {
            Address a = currentProgram.getAddressFactory().getAddress(args[i]);
            Function target = fm.getFunctionContaining(a);
            if (target == null) { println("no function at " + args[i]); continue; }
            println("callers of " + target.getName() + ":");
            for (Function c : target.getCallingFunctions(monitor)) {
                println("  " + c.getName() + " @ " + c.getEntryPoint());
                callers.add(c);
            }
        }
        for (Function f : callers) {
            DecompileResults res = dec.decompileFunction(f, 60, monitor);
            if (res == null || !res.decompileCompleted()) continue;
            String nm = f.getName().replaceAll("[^A-Za-z0-9_]", "_");
            try (PrintWriter pw = new PrintWriter(new File(outdir, nm + ".c"))) {
                pw.print(res.getDecompiledFunction().getC());
            }
        }
        println("DumpCallers: wrote " + callers.size() + " caller functions");
    }
}
