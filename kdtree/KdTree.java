import edu.princeton.cs.algs4.Point2D;
import edu.princeton.cs.algs4.RectHV;
import edu.princeton.cs.algs4.StdOut;

import java.util.Queue;

public class KdTree {

    private Node root;


    private class Node {
        private Point2D point;
        private Node left, right;
        private int count;
        private int key;  /* 0:x, 1:y */

        private Node(Point2D point) {
            left = null;
            right = null;
            this.point = point;
            count = 0;
        }
    }

    public KdTree()                               // construct an empty set of points
    {
        root = null;
    }

    public boolean isEmpty()                      // is the set empty?
    {
        return root == null;
    }


    private int size(Node node) {
        if (node == null) return 0;
        return node.count;
    }

    public int size()                         // number of points in the set
    {
        return size(root);
    }

    private Node put(Node node, Point2D p) {
        if (node == null) return new Node(p);

        int cmp = p.compareTo(node.point);
        if (cmp < 0) node.left = put(node.left, p);
        else if (cmp > 0) node.right = put(node.right, p);
        else node.point = p;
        node.count = 1 + size(node.left) + size(node.right);
        return node;
    }


    public void insert(Point2D p)              // add the point to the set (if it is not already in the set)
    {
        if (p == null) throw new java.lang.IllegalArgumentException();
        root = put(root, p);
    }


    public boolean contains(Point2D p)            // does the set contain point p?
    {
        if (p == null) throw new java.lang.IllegalArgumentException();
        Node node = root;
        int cmp = 0;
        while (node != null) {
            cmp = p.compareTo(node.point);
            if (cmp < 0) node = node.left;
            else if (cmp > 0) node = node.right;
            else return true;
        }
        return false;
    }

    public void draw()                         // draw all points to standard draw
    {
        Queue<Point2D> q = new Queue<Point2D>();
        if (root == null) throw new java.lang.IllegalArgumentException();
        Interable<Point2D> itr = inorder(root, q);
        for (auto pt : itr) {
            pt.draw();
        }
    }

    private void inorder(Node node, Queue<Point2D> q) {
        if (node == null) return;
        inorder(node.left, q);
        q.enqueue(node.point);
        inorder(node.right, q);
    }

    public Iterable<Point2D> range(RectHV rect)             // all points that are inside the rectangle (or on the boundary)
    {
        if (root == null || rect == null) throw new java.lang.IllegalArgumentException();
        Queue<Point2D> q = new Queue<Point2D>();
        Point2D rightLimit = new Point2D(rect.xmax(), rect.ymax());
        Point2D leftLimit = new Point2D(rect.xmin(), rect.ymin());


        return q;
    }

    public Point2D nearest(Point2D p)             // a nearest neighbor in the set to point p; null if the set is empty
    {
        Point2D point = null;
        Node node = root;
        int cmp = 0;
        double dist = 0.0;
        double mindist = 0.0;
        if (root == null) throw new java.lang.IllegalArgumentException();

        while (node != null) {
            cmp = p.compareTo(node.point);
            dist = p.distanceTo(node.point);
            if (mindist == 0.0) mindist = dist;
            if (mindist > dist) {
                point = node.point;
                mindist = dist;
            }

            if (cmp < 0) node = node.left;
            else if (cmp > 0) node = node.right;
            else break;
        }

        StdOut.println("nearest " + point.toString());
        return point;
    }

    public static void main(String[] args)                  // unit testing of the methods (optional)
    {

    }
}
