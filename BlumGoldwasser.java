
import java.io.*;
import java.lang.*;
import java.nio.ByteBuffer;
import java.util.*;
import java.math.*;
import java.util.concurrent.ThreadLocalRandom;
import java.net.*;

public class BlumGoldwasser {
    //Euclid's algorithm: pa + qb = 1
    final static int p = 499;
    final static int q = 547;
    final static int a = -57;
    //final static int aPos = 272896; //-57 is equivalent to 272896 mod n=272953
    final static int b = 52;
    final static int x0 = 159201;
    public static void main(String[] args) {
        String msg = "10011100000100001100";
        int n = p*q; //n is a Blum Integer
        System.out.println("n = " + n);
        int k = 18; //floor of log(n), value from class lecture
        int h = 4; //floor of log(k), value from class lecture

        BigInteger x0big = new BigInteger(Integer.toString(x0));
        BigInteger Nbig = new BigInteger(Integer.toString(n));
        BigInteger square = new BigInteger("2");

        /////encryption
        List<String> mBlocks = split(msg, 4);
        int t = mBlocks.size(); //msg m has t blocks of size h. for this example, t=5
        System.out.println("Msg m " + msg + " has " + t + " blocks of size " + h);

        List<String> Xi_string = new ArrayList<>();
        List<String> Pi_string = new ArrayList<>();
        String x0_string = Integer.toBinaryString(x0);
        Xi_string.add(x0_string);
        int[] Xi = new int[t+1];
        Xi[0] = x0;
        ArrayList<Integer> XiList = new ArrayList<>();
        XiList.add(x0);
        ArrayList<BigInteger> XiBig = new ArrayList<>();
        XiBig.add(x0big);

        //System.out.println((int)Math.pow(162396, 2));

        //encryption
        for(int i = 1; i<=t; i++) { //generate x_t+1
            BigInteger prev = XiBig.get(i-1);
            BigInteger entry = prev.modPow(square, Nbig);
            XiBig.add(entry);

            int toAdd = entry.intValue();
            //System.out.println("Value to be added: " + toAdd);
            XiList.add(toAdd);

            //System.out.println(XiList.get(i));

            String Xi_stringEntry = Integer.toBinaryString(XiList.get(i));
            //p_i should be the h least-significant bits of x_i
            String Pi_stringEntry = Xi_stringEntry.substring(Xi_stringEntry.length()-h);

            Xi_string.add(Xi_stringEntry);
            Pi_string.add(Pi_stringEntry);
        }

        //System.out.println("t + 1 = " + (t+1));
        //System.out.println("Xi size: " + XiList.size());

        //int xt1_int = (Xi[Xi.length-1]*Xi[Xi.length-1])%n;

        BigInteger xt1_big = XiBig.get(XiBig.size()-1).modPow(square, Nbig);
        int xt1_int = xt1_big.intValue();
        String xt1 = Integer.toBinaryString(xt1_int);

        //int[] Ci = new int[t+1];
        List<String> Ci_string = new ArrayList<>();
        //c_i = p_i XOR m_i
        //ciphertext C = (c1 ... ct, x_t+1)
        for(int i = 0; i<t; i++) {
            StringBuilder sb = new StringBuilder();
            //both mi and pi are of size h = 4
            String mi = mBlocks.get(i);
            String pi = Pi_string.get(i);
            for(int j = 0; j < h; j++) {
                sb.append(charOf(bitOf(pi.charAt(j)) ^ bitOf(mi.charAt(j))));
            }
            String ci = sb.toString();
            Ci_string.add(ci);
        }
        Ci_string.add(xt1);
        String Ci = String.join("", Ci_string);

        System.out.println("Ciphertext generated: " + Ci);

        ///////decryption
        //calculate d1, d2
        int p1 = (p+1);
        int q1 = (q+1);

        int d1_base = p1/4;
        int d1 = 1;
        for(int i=0; i<t+1; i++) {
            d1 = (d1*d1_base)%(p-1); //%(p-1)
        }
//        System.out.println("d1_base: " + d1_base);
//        System.out.println("d1: " + d1);

        int d2_base = q1/4;
        int d2 = 1;
        for(int i=0; i<t+1; i++) {
            d2 = (d2*d2_base)%(q-1); //%(q-1)
        }
//        System.out.println("d2_base: " + d2_base);
//        System.out.println("d2: " + d2);

        //calculate u, v
        //v = (x_t+1)^d2
        int v = 1;
        for(int i=0; i<d2; i++) {
            v = (v*xt1_int)%q;
        }
        //u = (x_t+1)^d1
        int u = 1;
        for(int i=0; i<d1; i++) {
            u = (u*xt1_int)%p;
        }

        //recalculate x0 = ((v*a*p)+(u*b*q))%n
        int part1 = v*a*p;
        //int part1modn = part1%n;
        if(part1 < 0) {
            part1 += n;
        }
        //System.out.println("v*a*p = " + part1);
        //System.out.println("v*a*p mod n = " + part1modn);
        int part2 = u*b*q;
        //int part2modn = part2%n;
        //System.out.println("u*b*q = " + part2);
        int part3 = part1+part2;
        //System.out.println("part1+part2 = " + part3);
        int x0_test = part3%n;
        if(x0_test < 0) {
            x0_test += n;
        }
        //System.out.println("x0 = " + x0);
        //System.out.println("x0 test = " + x0_test);
        if(x0_test == x0) {
            System.out.println("x0 seed recovered, decryption currently successful!");
        }

        //calculate message blocks m_i = c_i XOR p_i
        List<String> Mi_string = new ArrayList<>();
        //m_i = p_i XOR c_i
        for(int i = 0; i<t; i++) {
            StringBuilder sb = new StringBuilder();
            //both mi and pi are of size h = 4
            String ci = Ci_string.get(i);
            String pi = Pi_string.get(i);
            for(int j = 0; j < h; j++) {
                sb.append(charOf(bitOf(pi.charAt(j)) ^ bitOf(ci.charAt(j))));
            }
            String mi = sb.toString();
            Mi_string.add(mi);
        }
        //Mi_string.add(xt1);

        String Mi = String.join("", Mi_string);

        System.out.println("Plaintext recovered: " + Mi);

        if(msg.equals(Mi)) {
            System.out.println("Decryption was a success!");
        }

    }

    public static List<String> split(String text, int size) {
        List<String> output = new ArrayList<String>((text.length() + size - 1)/size);

        for(int start=0; start < text.length(); start += size) {
            output.add(text.substring(start, Math.min(text.length(), start+size)));
        }
        return output;
    }

    public static boolean bitOf(char in) {
        return (in == '1');
    }

    public static char charOf(boolean in) {
        return (in) ? '1' : '0';
    }
}
