import edu.princeton.cs.algs4.StdIn;

public class Permutation {
    public static void main(String[] args) {
        if (args.length == 0) System.out.println(" the number of arguments are not specified");
        int k = Integer.parseInt(args[0]);

        RandomizedQueue<String> randomizedQueue = new RandomizedQueue<String>();
        while (StdIn.isEmpty() == false) {
            String str = StdIn.readString();
            randomizedQueue.enqueue(str);
        }
        while (k > 0) {
            System.out.println(randomizedQueue.dequeue());
            k--;
        }
        return;
    }
}
