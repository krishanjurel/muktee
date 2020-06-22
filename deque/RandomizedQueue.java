import edu.princeton.cs.algs4.StdRandom;

import java.util.Iterator;

public class RandomizedQueue<Item> implements Iterable<Item> {
    private Item[] items;
    /* head and tial */
    private int head;
    private int tail;
    /* number of items */
    private int arraySize;

    /* default constructor */
    public RandomizedQueue() {
        head = 0;
        tail = 0;
        items = null;
        arraySize = 0;
    }


    /* public methods */
    public boolean isEmpty() {
        return tail == 0;
    }

    public int size() {
        return tail;
    }

    /* resize array */
    private void resize(int n) {
        /* java does not allow generic arrays, have to cast it */
        Item[] tempArray = (Item[]) new Object[n];
        int j = 0;
        for (int i = head; i < tail; i++, j++) {
            tempArray[j] = items[i];
        }
        items = tempArray;
        arraySize = n;
        /* re adjust the head and tail */
        head = 0;
        tail = j;
    }


    /* add first item at front */
    public void enqueue(Item item) {
        if (item == null) throw new IllegalArgumentException();
        if (arraySize == tail) {
            if (arraySize == 0) arraySize = 1;
            resize(2 * arraySize);
        }
        items[tail] = item;
        /* increase the tail */
        tail++;
    }

    public Item dequeue() {
        if (tail == 0) throw new java.util.NoSuchElementException();
        if (tail == arraySize / 4) resize(arraySize / 2);
        int i = StdRandom.uniform(head, tail);
        Item item = items[i];
        /* adjust the number of items remaining */
        --tail;
        items[i] = items[tail];
        items[tail] = null;
        return item;
    }

    public Item sample() {
        if (tail == 0) throw new java.util.NoSuchElementException();
        return items[StdRandom.uniform(head, tail)];

    }

    private class ListIterator implements Iterator<Item> {
        final private int h = head;
        private int t = tail;
        private Item[] nodes = items;

        public boolean hasNext() {
            return t != 0;
        }

        public Item next() {
            if (hasNext() == false) throw new java.util.NoSuchElementException();
            int i = StdRandom.uniform(h, t);
            --t;
            Item item = nodes[i];
            nodes[i] = nodes[t];
            nodes[t] = item;
            return item;
        }

        public void remove() {
            throw new UnsupportedOperationException();
        }
    }

    public Iterator<Item> iterator() {
        return new ListIterator();
    }


    // unit testing
    public static void main(String[] args) {
        RandomizedQueue<Integer> randomizedQueue = new RandomizedQueue<Integer>();
        randomizedQueue.enqueue(1);
        //System.out.println(randomizedQueue.dequeue());
        randomizedQueue.enqueue(2);
        //System.out.println(randomizedQueue.dequeue());
        randomizedQueue.enqueue(3);
        //System.out.println(randomizedQueue.dequeue());
        randomizedQueue.enqueue(4);
        //System.out.println(randomizedQueue.dequeue());
        randomizedQueue.enqueue(5);
        randomizedQueue.enqueue(6);
        //System.out.println(randomizedQueue.dequeue());
        //System.out.println(randomizedQueue.dequeue());
        randomizedQueue.enqueue(7);

        for (int i = 8; i < 20; i++) {
            randomizedQueue.enqueue(i);
        }

        Iterator<Integer> itr = randomizedQueue.iterator();
        Iterator<Integer> itr2 = randomizedQueue.iterator();
        while (itr.hasNext())
            System.out.println(itr.next());

        while (itr2.hasNext())
            System.out.println(itr2.next());


    }
}
