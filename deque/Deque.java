import java.util.Iterator;

public class Deque<Item> implements Iterable<Item> {
    /* internal class */
    private class Node {
        Item item;
        Node next;
        Node prev;

        public Node() {
            prev = null;
            next = null;
        }
    }

    /* head and tial */
    private Node head;
    private Node tail;
    /* number of items */
    private int items;

    /* default constructor */
    public Deque() {
        head = null;
        tail = null;
        items = 0;
    }


    /* public methods */
    public boolean isEmpty() {
        return items == 0;
    }

    public int size() {
        return items;
    }

    /* add first item at front */
    public void addFirst(Item item) {

        if (item == null) throw new IllegalArgumentException();
        Node node = new Node();
        node.item = item;
        node.next = head;
        /* heads previous points to null */
        node.prev = null;
        /* take care of the only head */
        if (head != null) head.prev = node;
        /* readjust the head */
        head = node;
        if (items == 0) tail = head;
        /* increments the number of items */
        items++;
    }

    /* add last */
    public void addLast(Item item) {
        if (item == null) throw new IllegalArgumentException();
        if (head == null) addFirst(item);
        else {
            /* this is new tail */
            Node node = new Node();
            node.item = item;
            node.next = null;
            node.prev = tail;
            tail.next = node;
            /* set the new tail*/
            tail = node;
            /* increment the number of items */
            items++;
        }
    }

    public Item removeFirst() {
        if (items == 0) throw new java.util.NoSuchElementException();
        Item item = head.item;

        /* adjust the number of items remaining */
        items--;
        /* new head */
        Node node = head.next;
        if (items > 0) {
            /* adjust the tail the previous one */
            node.prev = null;
        }
        /* new head */
        head = node;
        if (head == null) tail = null;

        return item;
    }

    /* remove last */
    public Item removeLast() {
        if (items == 0) throw new java.util.NoSuchElementException();
        Item item = tail.item;

        /* remaining items */
        items--;
        /* new tail */
        Node node = tail.prev;

        if (items > 0) {
            node.next = null;
        }
        tail = node;
        if (tail == null) head = null;
        return item;
    }

    private class ListIterator implements Iterator<Item> {
        private Node current = head;
        private int nodes = items;

        public boolean hasNext() {
            return nodes != 0;
        }

        public Item next() {
            if (hasNext() == false) throw new java.util.NoSuchElementException();

            Item item = current.item;
            current = current.next;
            nodes--;
            // current.prev = tail;
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
        Deque<Integer> deque = new Deque<Integer>();

        deque.addFirst(1);
        deque.addLast(2);
        deque.addFirst(3);
        deque.addLast(4);
        deque.addLast(5);
        deque.addFirst(6);

        deque.removeLast();
        deque.removeLast();
        deque.addLast(2);
        deque.addFirst(3);
        deque.removeFirst();
        deque.removeLast();
        deque.removeFirst();
        deque.removeLast();
        deque.addLast(5);
        deque.addFirst(6);
        deque.removeLast();
        deque.removeLast();
        deque.addFirst(1);
        deque.addLast(4);


        Iterator<Integer> itr = deque.iterator();
        while (itr.hasNext())
            System.out.println(itr.next());

    }
}
