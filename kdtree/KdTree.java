import edu.princeton.cs.algs4.Point2D;
import edu.princeton.cs.algs4.RectHV;
import edu.princeton.cs.algs4.StdOut;

import java.util.Vector;

public class KdTree {

    private Node root;


    private class Node {
        private double x;
        private double y;
        private double maxy;
        private Point2D point;
        private Node left, right;
        private int count;
        private double key;

        private Node(Point2D point) {
            left = null;
            right = null;
            this.point = point;
            x = point.x();
            y = point.y();
            maxy = y;
            count = 0;
            key = x;
        }


        private Node(Point2D point, double key) {
            left = null;
            right = null;
            this.point = point;
            x = point.x();
            y = point.y();
            maxy = y;
            count = 0;
            this.key = key;
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

    private int compareTo(double ths, double that) {
        int ret = 0;
        if (ths < that) ret = -1;
        else if (ths > that) ret = 1;
        else ret = 0;
        return ret;
    }

    private Node put(Node node, Point2D p) {
        double x;
        if (node == null) return new Node(p);

        /* update the maxy of every parent along the way */
        if (node.maxy < p.y())
            node.maxy = p.y();

        int cmp = compareTo(p.x(), node.point.x());//p.compareTo(node.point);
        int cmpy = compareTo(p.y(), node.point.y());
        if (cmp < 0) node.left = put(node.left, p);
        else if (cmp > 0) node.right = put(node.right, p);
        else {
            if (cmpy < 0) node.left = put(node.left, p);
            if (cmpy > 0) node.right = put(node.right, p);
            else node.point = p;
        }
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
            cmp = compareTo(p.x(), node.point.x());//p.compareTo(node.point);
            if (cmp < 0) node = node.left;
            else if (cmp > 0) node = node.right;
            else return true;
        }
        return false;
    }

    public void draw()                         // draw all points to standard draw
    {
        Vector<Point2D> q = new Vector<Point2D>();
        if (root == null) throw new java.lang.IllegalArgumentException();
        inorder(root, q);
        Iterable<Point2D> itr = q; //q.toArray(new Point2D[q.size()]);
        for (Point2D pt : itr) {
            StdOut.println("draw " + pt.toString());
            pt.draw();
        }
    }

    private void inorder(Node node, Vector<Point2D> q) {
        if (node == null) return;
        inorder(node.left, q);
        q.add(node.point);
        inorder(node.right, q);
    }


    private void range_traversal(Point2D low, Point2D hi, Node node, Vector<Point2D> vec) {
        if (node == null) return;
        double reflowx = low.x();
        double reflowy = low.y();
        double refhix = hi.x();
        double refhiy = hi.y();
        double x = node.x;
        double y = node.maxy;
        int cmplo = compareTo(x, reflowx);
        int cmphi = compareTo(x, refhix);

        if (cmplo < 0 || cmphi > 0) return;
        range_traversal(low, hi, node.left, vec);
        if (node.y <= refhiy) vec.add(node.point);
        range_traversal(low, hi, node.right, vec);
    }


    public Iterable<Point2D> range(RectHV rect)             // all points that are inside the rectangle (or on the boundary)
    {
        if (root == null || rect == null) throw new java.lang.IllegalArgumentException();
        Vector<Point2D> q = new Vector<Point2D>();
        Point2D rightLimit = new Point2D(rect.xmax(), rect.ymax());
        Point2D leftLimit = new Point2D(rect.xmin(), rect.ymin());
        range_traversal(leftLimit, rightLimit, root, q);
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

        Vector<Point2D> q = new Vector<Point2D>();
        if (root == null) throw new java.lang.IllegalArgumentException();
        inorder(root, q);
        Iterable<Point2D> itr = q;

        for (Point2D pt : itr) {
            dist = p.distanceTo(pt);
            if (mindist == 0.0) {
                point = pt;
                mindist = dist;
            }

            if (mindist > dist) {
                mindist = dist;
                point = pt;
            }
        }
        if (point == null) throw new java.lang.IllegalArgumentException();
        StdOut.println("kd nearest " + point.toString());
        return point;
    }

    public static void main(String[] args)                  // unit testing of the methods (optional)
    {

    }
}
