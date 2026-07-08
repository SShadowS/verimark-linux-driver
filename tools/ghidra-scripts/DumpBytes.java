import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
public class DumpBytes extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) { println("usage: DumpBytes <outfile> <hexaddr> <len>"); return; }
        Address a = currentProgram.getAddressFactory().getAddress(args[1]);
        int len = Integer.decode(args[2]);
        byte[] buf = new byte[len];
        currentProgram.getMemory().getBytes(a, buf);
        java.io.FileOutputStream f = new java.io.FileOutputStream(args[0]);
        f.write(buf); f.close();
        println("wrote " + len + " bytes from " + args[1] + " to " + args[0]);
    }
}
