// AutoNameFromStrings.java — recover symbolic names for functions from the driver's
// own self-logging strings. synaWudfBioUsb132.dll logs "CClass::Method" / "tudorXxx"
// names inside the very functions they name, so the function that references such a
// string can be renamed to it. Applies the 122 C++ names + 503 tudor*/ssiTls* anchors.
//
// Heuristic (conservative, first-wins): a string whose leading token is a
// Class::method or a known-prefix identifier names its *sole* referencing function,
// but only if that function is still default-named (FUN_/no user symbol). Safe for a
// first pass; dispatcher functions that log many names keep their first assignment.
//
// @category verimark
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.*;
import java.util.regex.*;

public class AutoNameFromStrings extends GhidraScript {
    // leading Class::method  OR  known Synaptics/Tudor function-name prefixes
    static final Pattern PAT = Pattern.compile(
        "^([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+)" +
        "|^((?:tudor|ssiTls|pal|nise|Wbio|Vfm|prf|Tudor|EngineAdapter|SensorAdapter|StorageAdapter)[A-Za-z0-9_]+)");

    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        ReferenceManager rm = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();
        int named = 0, seen = 0;
        Set<Function> alreadyThisPass = new HashSet<>();

        DataIterator di = listing.getDefinedData(true);
        while (di.hasNext() && !monitor.isCancelled()) {
            Data d = di.next();
            if (d == null) continue;
            Object v = d.getValue();
            if (!(v instanceof String)) continue;
            String s = ((String) v).trim();
            Matcher m = PAT.matcher(s);
            if (!m.find() || m.start() != 0) continue;
            String name = (m.group(1) != null) ? m.group(1) : m.group(2);
            if (name == null || name.length() < 4) continue;
            seen++;

            // functions that reference this string
            Set<Function> funcs = new HashSet<>();
            ReferenceIterator ri = rm.getReferencesTo(d.getAddress());
            while (ri.hasNext()) {
                Reference r = ri.next();
                Function f = fm.getFunctionContaining(r.getFromAddress());
                if (f != null) funcs.add(f);
            }
            if (funcs.size() != 1) continue;
            Function f = funcs.iterator().next();
            if (alreadyThisPass.contains(f)) continue;
            Symbol sym = f.getSymbol();
            boolean isDefault = (sym == null) || (sym.getSource() == SourceType.DEFAULT)
                                 || f.getName().startsWith("FUN_");
            if (!isDefault) continue;

            String clean = name.replaceAll("[^A-Za-z0-9_]", "_");
            try {
                f.setName(clean, SourceType.USER_DEFINED);
                alreadyThisPass.add(f);
                named++;
            } catch (Exception e) { /* duplicate/invalid — skip */ }
        }
        println("AutoNameFromStrings: matched " + seen + " name-like strings, renamed " + named + " functions");
    }
}
