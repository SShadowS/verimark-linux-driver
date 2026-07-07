// DumpFunctions.java — decompile every function whose (sanitized) name contains any
// of the given keywords, writing each to <outdir>/<name>.c plus an _index.txt.
// Run AFTER AutoNameFromStrings so the target functions are named.
//
//   -postScript DumpFunctions.java <outdir> <kw1> [kw2] ...
// @category verimark
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;
import java.util.*;

public class DumpFunctions extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) { println("usage: DumpFunctions <outdir> <kw1> [kw2...]"); return; }
        File outdir = new File(args[0]); outdir.mkdirs();
        List<String> kws = new ArrayList<>();
        for (int i = 1; i < args.length; i++) kws.add(args[i].toLowerCase());

        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);

        FunctionManager fm = currentProgram.getFunctionManager();
        StringBuilder index = new StringBuilder();
        int n = 0;
        for (Function f : fm.getFunctions(true)) {
            if (monitor.isCancelled()) break;
            String low = f.getName().toLowerCase();
            boolean match = false;
            for (String k : kws) if (low.contains(k)) { match = true; break; }
            if (!match) continue;

            DecompileResults res = dec.decompileFunction(f, 60, monitor);
            if (res == null || !res.decompileCompleted()) continue;
            String c = res.getDecompiledFunction().getC();
            String fname = f.getName().replaceAll("[^A-Za-z0-9_]", "_");
            if (fname.length() > 120) fname = fname.substring(0, 120);
            try (PrintWriter pw = new PrintWriter(new File(outdir, fname + ".c"))) { pw.print(c); }
            index.append(String.format("%-70s @ %s  (%d bytes, %d callers)%n",
                f.getName(), f.getEntryPoint(), f.getBody().getNumAddresses(),
                f.getCallingFunctions(monitor).size()));
            n++;
        }
        try (PrintWriter pw = new PrintWriter(new File(outdir, "_index.txt"))) { pw.print(index.toString()); }
        println("DumpFunctions: wrote " + n + " decompiled functions to " + outdir);
    }
}
