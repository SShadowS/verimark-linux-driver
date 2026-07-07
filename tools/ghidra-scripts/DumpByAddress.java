// DumpByAddress.java — decompile the function containing each given address to
// <outdir>/<name>.c. For reaching unnamed FUN_ transport helpers by address.
//   -postScript DumpByAddress.java <outdir> <hexaddr1> [hexaddr2] ...
// @category verimark
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import java.io.*;

public class DumpByAddress extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) { println("usage: DumpByAddress <outdir> <addr>..."); return; }
        File outdir = new File(args[0]); outdir.mkdirs();
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        for (int i = 1; i < args.length; i++) {
            Address a = currentProgram.getAddressFactory().getAddress(args[i]);
            if (a == null) { println("bad addr " + args[i]); continue; }
            Function f = fm.getFunctionContaining(a);
            if (f == null) { println("no function at " + args[i]); continue; }
            DecompileResults res = dec.decompileFunction(f, 60, monitor);
            if (res == null || !res.decompileCompleted()) { println("decomp failed " + args[i]); continue; }
            String nm = f.getName().replaceAll("[^A-Za-z0-9_]", "_");
            try (PrintWriter pw = new PrintWriter(new File(outdir, nm + ".c"))) {
                pw.print(res.getDecompiledFunction().getC());
            }
            println("wrote " + nm + " (" + f.getEntryPoint() + ")");
        }
    }
}
